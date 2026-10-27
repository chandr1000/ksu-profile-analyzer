# Pipeline: Runtime strace analysis

When static analysis is inconclusive (packed binary, stripped, obfuscated, ambiguous syscalls), use runtime strace to capture the actual syscall surface. This pipeline parses strace output files and maps them through the **same** `reference/syscall_to_cap.md` table as the static pipelines.

## Inputs

- `target`: directory of strace log files (typically produced by the user running `strace_capture.sh` on device, then `adb pull`-ing the result to their PC).

## Tools

| Tool | Used for |
|---|---|
| Python stdlib (`re`, `json`, `os`) | Parse strace output |
| `find` | Locate log files in the input dir |

## The strace_capture.sh helper

Ships with the skill under `templates/strace_capture.sh`. Its job:

1. `adb push` itself to `/data/local/tmp/`
2. Make executable
3. Take a `<package_name>` argument
4. Force-stop the app, then launch it under `strace -ff -y -e trace=%file,%desc,%network,%process,%signal,%memory,%ipc -o /sdcard/ksu_strace_<pkg>/trace`
   - **`-y` is MANDATORY**: it annotates every fd argument with the file path (e.g. `write(3</sys/kernel/config/usb_gadget/g1/UDC>, "", 0)`), which is what the parser needs to map `write()`/`read()` calls to capabilities.
   - **`%desc` is MANDATORY**: it captures `read`/`write`/`pwrite`/`pread`/`writev`/`readv`/`sendfile`/`splice`/`copy_file_range`/`tee`/`vmsplice`. Without it, strace only captures `openat()` (the file opens) but NOT the subsequent `write()`/`read()` that actually performs the privileged operation and returns EACCES.
   - On old strace versions (<5.3) where `%desc` isn't supported, use the explicit form: `-e trace=%file,read,write,pwrite,pread,writev,readv,%network,%process,%signal,%memory,%ipc`.
   - For maximum coverage (much larger logs, slower): `-e trace=all`.
5. Run for a configurable duration (default 30s) or until killed
6. Tell the user to `adb pull /sdcard/ksu_strace_<pkg>/ ./strace_logs/` and re-invoke the skill with `--from-strace ./strace_logs/`

The helper handles the su-vs-not-su distinction: the strace itself needs root to attach to other processes, so it runs as root via `su -c`. The captured app processes retain their normal (non-root) UID — the trace shows what syscalls they make under their normal privileges, which is exactly what we want for capability analysis.

## Strace output format

With `-ff`, strace creates one file per traced PID:

```
trace.<pid1>
trace.<pid2>
trace.<pid3>
...
```

Each file contains lines like (note the `-y` fd→path annotation in parentheses):

```
[pid 1234] mount("/dev/block/sda1", "/mnt/foo", "ext4", 0, NULL) = 0
[pid 1234] setuid(0)               = 0
[pid 1235] ptrace(PTRACE_ATTACH, 1234, NULL, NULL) = 0
[pid 1234] socket(AF_PACKET, SOCK_RAW, 0x88a8) = 3
[pid 1234] bind(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0
[pid 1235] openat(AT_FDCWD, "/dev/mem", O_RDWR) = -1 EACCES (Permission denied)
[pid 1234] write(3</sys/kernel/config/usb_gadget/g1/UDC>, "", 0) = -1 EACCES (Permission denied)
[pid 1234] write(4</sys/kernel/config/usb_gadget/usb_arsenal/UDC>, "a600000.dwc3\n", 15) = -1 EBUSY (Device or resource busy)
```

The last two lines are CRITICAL signals that the previous filter `%file,%network,...` (without `%desc`) would have MISSED entirely. The `write(3</sys/.../g1/UDC>, "", 0) = -1 EACCES` is the upstream failure that downstream manifests as `write(4</sys/.../usb_arsenal/UDC>, ...) = -1 EBUSY`. Without `-y`, both `write(3, ...)` and `write(4, ...)` would lack the path annotation, and the parser couldn't map them to capabilities. The proper fix is `CAP_DAC_OVERRIDE` for the upstream write.

## Parsing rules

### 1. Extract syscall name from each line

Regex: `^\s*(?:\[pid \d+\] )?(\w+)\(`

Skip lines that don't match — they're strace commentary (e.g. `--- SIGCHLD ---`).

### 2. Extract arguments for special cases

Some syscalls need argument inspection to determine the correct capability:

- `bind(fd, {sa_family=..., sin_port=htons(N)}, ...)`: parse N. If N < 1024 → `CAP_NET_BIND_SERVICE`. Otherwise, no capability.
- `socket(AF_PACKET, SOCK_RAW, ...)`: → `CAP_NET_RAW`. The family + type are in the first two args.
- `socket(AF_INET, SOCK_RAW, ...)` or `socket(AF_INET6, SOCK_RAW, ...)`: → `CAP_NET_RAW`.
- `clone(CLONE_NEWNS|CLONE_NEWPID|...)`: parse flags. If any CLONE_NEW* (except NEWUSER) → `CAP_SYS_ADMIN`.
- `setns(fd, CLONE_NEWNS|...)`: same.
- `setsockopt(fd, SOL_SOCKET, SO_DEBUG|SO_MARK|SO_PRIORITY|SO_RCVBUFFORCE|SO_SNDBUFFORCE, ...)`: parse the option name → `CAP_NET_ADMIN`.
- `setxattr(path, "security.<X>", ...)`: parse the attribute name. `"security.capability"` → `CAP_SETFCAP`. `"security.*"` → `CAP_SYS_ADMIN` (ambiguous).
- `openat(..., "<path>", O_RDONLY|...)`: check the path. `/dev/mem` → `CAP_SYS_RAWIO`. `/proc/<pid>/maps` (not own pid) → `CAP_SYS_PTRACE`. `/sys/kernel/tracing/*` → `CAP_SYS_ADMIN` + `CAP_PERFMON` + group 3012.
- `execve("/system/xbin/su", ...)` or `execve("/system/bin/su", ...)`: → su_invocation signal, set `allowSu=true` in Pass 2.

### 3. Skip syscall noise

Many syscalls are normal for any app and don't imply privileges:

- `read`, `write`, `openat`, `close` (to regular files in the app's own data dir)
- `fstat`, `stat`, `lstat`, `newfstatat`
- `mmap`, `munmap`, `mprotect`, `brk`
- `rt_sigprocmask`, `rt_sigaction`, `rt_sigreturn`
- `futex`, `gettid`, `getpid`, `getuid`, `getgid`
- `clock_gettime`, `gettimeofday` (read-only)
- `socket(AF_UNIX, SOCK_STREAM|SOCK_DGRAM, ...)` (local sockets — no cap needed)
- `connect(AF_UNIX, ...)`
- `epoll_wait`, `epoll_ctl`, `ppoll`, `pselect6`
- `ioctl` to regular files (TIOCGWINSZ, etc.)

The `syscall_to_cap.md` table only contains syscalls that imply a capability — anything not in the table is normal.

### 4. Aggregate per-syscall counts

For each distinct syscall name + variant (e.g. `bind(port=80)` vs `bind(port=8080)`), record:

- Count of invocations
- Sample line from the trace (first occurrence)
- Confidence: `unambiguous` (direct syscall match) or `ambiguous` (e.g. `setrlimit` could be raising OR lowering)

### 5. Tag signals as `source: "strace"`

Every signal from this pipeline is tagged `source: "strace:trace.<pid>"` so the merged `findings.json` can show what came from runtime vs static.

## Merging with static findings

When both static and strace findings exist for the same capability, the merge rule is:

- If **either** source flags a capability as `unambiguous`, the merged entry is `unambiguous` with `source: "static+strace"` and both evidence lines recorded.
- If only strace flags it (and static didn't find it), the merged entry is `unambiguous` from strace — strace is authoritative for what actually happened.
- If only static flags it (and strace didn't observe it during the capture window), the entry stays — the syscall may simply not have fired during the limited trace window. Tag `source: "static (not observed in strace)"` to flag the gap for the user.

## Output (findings.json shape)

Same schema as the other pipelines. Example:

```json
{
  "target": "/path/to/strace_logs",
  "target_type": "strace",
  "package_name": "com.example.foo",
  "capture_window_seconds": 30,
  "pids_traced": [1234, 1235, 1236],
  "signals": [
    {
      "kind": "syscall",
      "name": "bind(port=80)",
      "source": "strace:trace.1234",
      "evidence": "[pid 1234] bind(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0",
      "count": 1,
      "confidence": "unambiguous"
    },
    {
      "kind": "syscall",
      "name": "socket(AF_PACKET, SOCK_RAW)",
      "source": "strace:trace.1234",
      "evidence": "[pid 1234] socket(AF_PACKET, SOCK_RAW, 0x88a8) = 3",
      "count": 1,
      "confidence": "unambiguous"
    },
    {
      "kind": "file_path",
      "name": "/dev/mem",
      "source": "strace:trace.1235",
      "evidence": "[pid 1235] openat(AT_FDCWD, \"/dev/mem\", O_RDWR) = -1 EACCES (Permission denied)",
      "count": 1,
      "confidence": "unambiguous"
    }
  ]
}
```

## Limitations

- **Capture window bias**: strace only sees what happens during the capture. Long-running apps may exercise more privileges later. Recommend a longer capture for production apps (e.g. 5 minutes, exercise all features).
- **EACCES isn't proof of need**: if a syscall fails with EACCES in the trace, it means the app tried it but was denied. That's still a signal — the app *wants* this capability, so it should be added to the profile (the user can deny in Pass 2 if they don't want to grant it).
- **Forked children**: `strace -ff` follows forks. Each child gets its own trace file. The pipeline handles all of them.
- **Strace itself needs root**: the helper script handles this — it runs under `su -c`. The captured app processes still run with their normal UID.
- **Performance impact**: strace has 2-10x overhead. Apps that depend on real-time performance (e.g. games) may behave differently under strace. Document this in `analysis.md` when the helper is recommended.
- **Filter coverage**: the helper now uses `-e trace=%file,%desc,%network,%process,%signal,%memory,%ipc` which **includes `%desc`** (the file-descriptor syscall class — read/write/pwrite/pread/writev/readv/sendfile/splice/copy_file_range/tee/vmsplice). The previous filter `%file,%network,...` (without `%desc`) was a real bug that captured `openat()` calls but missed ALL `write()`/`read()` calls — hiding EACCES denials on `write()` to configfs / dev nodes that needed `CAP_DAC_OVERRIDE`.
- **`-y` flag is MANDATORY**: it prints the file path associated with each fd argument. Without it, `write(3, ...)` / `read(3, ...)` lines don't include the path, and the parser cannot map them to capabilities. The helper now always passes `-y`.
- **For full coverage** (much larger logs, slower): use `-e trace=all` instead of the category-filtered form.
- **Old strace compatibility**: if `%desc` is not supported (strace < 5.3), use the explicit form `-e trace=%file,read,write,pwrite,pread,writev,readv,%network,...`.

## When this pipeline is triggered

The skill triggers this pipeline when:

1. Static analysis reported `stripped_binary` or `packed_binary` signals, OR
2. The user explicitly asks for `--from-strace <dir>` mode, OR
3. The user opts into Pass 2 with "I have strace logs, here's the path".
