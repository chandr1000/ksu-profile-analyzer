# Pipeline: Source repo analysis

Extract signals from a source code repository (Android project, native C/C++ project, Go, Rust, etc.).

## Inputs

- `target`: absolute path to the repo directory (or a git URL — clone first if remote)

## Tools

| Tool | Used for |
|---|---|
| `ripgrep` (rg) | Fast source-code scanning |
| `tree-sitter` (optional) | AST-aware scanning for false-positive reduction |
| `git` | Clone if remote |
| `apktool` / `aapt2` | If the repo includes a prebuilt APK in `app/` or `releases/` — fall back to `pipelines/apk.md` |
| `find` | Locate build files (`build.gradle*`, `AndroidManifest.xml`, `Cargo.toml`, `go.mod`, `CMakeLists.txt`) |

## Workflow

### 1. Identify project type

```sh
# Android (Gradle):
test -f build.gradle.kts || test -f build.gradle && echo "android-gradle"

# Android (Bazel):
test -f WORKSPACE && grep -q android BUILD.bazel 2>/dev/null && echo "android-bazel"

# Native C/C++:
test -f CMakeLists.txt && echo "native-cmake"
test -f Makefile && echo "native-make"

# Rust:
test -f Cargo.toml && echo "rust"

# Go:
test -f go.mod && echo "go"
```

### 2. If Android project — extract manifest permissions

```sh
# Find the manifest:
MANIFEST=$(find . -name AndroidManifest.xml | grep -v build/ | head -1)

# If it's compiled (binary XML), use aapt2:
aapt2 dump permissions "$MANIFEST" 2>/dev/null > perms.txt
# If it's source XML, just grep:
grep -oE 'android:name="[^"]*"' "$MANIFEST" | sed 's/android:name="//;s/"//' | sort -u > perms.txt
```

Parse `perms.txt` and look up in `reference/syscall_to_cap.md` (the "AndroidManifest permissions" section).

### 3. Scan source code for direct syscalls / privileged ops

Use ripgrep patterns. Each match becomes a signal — the file:line is recorded as `evidence`.

#### C / C++ (`.c`, `.cpp`, `.h`, `.cc`)

```sh
rg --type c --line-number \
  -e '\bsetuid\s*\(' \
  -e '\bsetgid\s*\(' \
  -e '\bsetresuid\s*\(' \
  -e '\bsetresgid\s*\(' \
  -e '\bsetfsuid\s*\(' \
  -e '\bsetfsgid\s*\(' \
  -e '\bsetgroups\s*\(' \
  -e '\bptrace\s*\(' \
  -e '\bprocess_vm_readv\s*\(' \
  -e '\bprocess_vm_writev\s*\(' \
  -e '\bkcmp\s*\(' \
  -e '\bmount\s*\(' \
  -e '\bumount2?\s*\(' \
  -e '\bpivot_root\s*\(' \
  -e '\bswapon\s*\(' \
  -e '\bswapoff\s*\(' \
  -e '\bsethostname\s*\(' \
  -e '\bsetdomainname\s*\(' \
  -e '\bquotactl\s*\(' \
  -e '\bsetns\s*\(' \
  -e '\bfanotify_init\s*\(' \
  -e '\bchroot\s*\(' \
  -e '\bmknod\s*\(' \
  -e '\bmknodat\s*\(' \
  -e '\breboot\s*\(' \
  -e '\bkexec_load\s*\(' \
  -e '\bkexec_file_load\s*\(' \
  -e '\binit_module\s*\(' \
  -e '\bfinit_module\s*\(' \
  -e '\bdelete_module\s*\(' \
  -e '\biopl\s*\(' \
  -e '\bioperm\s*\(' \
  -e '\bsettimeofday\s*\(' \
  -e '\badjtimex\s*\(' \
  -e '\bclock_settime\s*\(' \
  -e '\bvhangup\s*\(' \
  -e '\bacct\s*\(' \
  -e '\bbpf\s*\(' \
  -e '\bperf_event_open\s*\(' \
  -e '\bclone3\s*\(' \
  -e '\bsetrlimit\s*\(' \
  -e '\bprlimit\s*\(' \
  -e '\bmlock\s*\(' \
  -e '\bmlockall\s*\(' \
  -e '\bshmctl\s*\(' \
  -e '\bkill\s*\(' \
  -e '\btgkill\s*\(' \
  -e '\btkill\s*\(' \
  -e '\bpidfd_send_signal\s*\(' \
  -e '\bchown\s*\(' \
  -e '\bfchown\s*\(' \
  -e '\blchown\s*\(' \
  -e '\bfchownat\s*\(' \
  -e '\bsetxattr\s*\(' \
  -e '\bfsetxattr\s*\(' \
  -e '\bsetcap\s*\(' \
  -e '\bcapset\s*\(' \
  -e '\btimerfd_create\s*\(' \
  .
```

For each match, look up the function name in `reference/syscall_to_cap.md` (the "Imported libc symbols" section). The signal `confidence` is `unambiguous` for direct calls; `ambiguous` for calls inside `#ifdef` blocks or commented-out code (record the context).

#### Go (`.go`)

```sh
rg --type go --line-number \
  -e 'syscall\.Setuid' \
  -e 'syscall\.Setgid' \
  -e 'syscall\.Setgroups' \
  -e 'syscall\.Mount' \
  -e 'syscall\.Unmount' \
  -e 'syscall\.PivotRoot' \
  -e 'syscall\.Swapon' \
  -e 'syscall\.Swapoff' \
  -e 'syscall\.Sethostname' \
  -e 'syscall\.Ptrace' \
  -e 'syscall\.Reboot' \
  -e 'syscall\.Mknod' \
  -e 'unix\.' \
  .
```

Note: Go's `unix` package wraps raw syscalls — every call there is a potential privileged op.

#### Rust (`.rs`)

```sh
rg --type rust --line-number \
  -e 'nix::unistd::setuid' \
  -e 'nix::unistd::setgid' \
  -e 'nix::unistd::setgroups' \
  -e 'nix::mount::mount' \
  -e 'nix::mount::umount' \
  -e 'nix::sched::setns' \
  -e 'nix::unistd::chroot' \
  -e 'nix::unistd::ptrace' \
  -e 'libc::setuid' \
  -e 'libc::mount' \
  -e 'libc::ptrace' \
  -e 'libc::reboot' \
  -e 'libc::mknod' \
  .
```

#### Java / Kotlin (Android app source)

```sh
rg --type java --type kotlin --line-number \
  -e 'Runtime\.getRuntime\(\)\.exec\(' \
  -e 'ProcessBuilder\(' \
  -e 'com\.topjohnwu\.superuser' \
  -e 'com\.topjohnwu\.magisk' \
  -e 'Shell\.su\(' \
  -e 'Shell\.cmd\(' \
  -e 'new ServerSocket\(\s*[0-9]{1,3}\s*\)' \
  -e 'new DatagramSocket\(\s*[0-9]{1,3}\s*\)' \
  -e 'loadLibrary\(' \
  .
```

For each `loadLibrary("foo")` match, identify `lib<abi>/libfoo.so` in the project (or in any bundled APK in `releases/`), then recurse into `pipelines/binary.md` for that lib.

#### JNI declarations

```sh
# C/C++ side:
rg --type c --type c --line-number -e 'JNIEXPORT .*\s+(Java_[a-zA-Z0-9_]+)\s*\(' .

# Java side:
rg --type java --type kotlin --line-number -e 'native\s+\w+\s+\w+\(' .
```

Each JNI declaration on the Java side tells you what native methods the app expects to call. Cross-reference with the C/C++ implementation to determine which syscalls they invoke.

### 4. Scan for hardcoded paths

```sh
# Interesting file paths:
rg --all-files --line-number \
  -e '"/dev/[^"]+"' \
  -e '"/proc/[^"]+"' \
  -e '"/sys/[^"]+"' \
  -e '"/data/adb/[^"]+"' \
  -e '"/system/(xbin|bin)/su"' \
  -e '"/system/sbin/su"' \
  -e '"/sbin/su"' \
  .
```

Each match becomes a `file_path` signal. Look up in `reference/syscall_to_cap.md` (the "Device nodes" section).

### 5. Scan build files for declared permissions / features

```sh
# build.gradle(.kts) — permissions are sometimes declared as strings:
rg --glob 'build.gradle*' -e 'android\.permission\.'

# CMakeLists.txt — link dependencies hint at capability usage:
rg --glob 'CMakeLists.txt' -e 'target_link_libraries.*libcap' -e 'libselinux' -e 'libaudit' -e 'libbpf'
```

### 6. Identify su intent

Same priority as APK pipeline:

| Signal | Confidence |
|---|---|
| `Runtime.exec("su")` in Java source | unambiguous |
| `ProcessBuilder("su")` in Java source | unambiguous |
| `Shell.su(...)` (libsu) | unambiguous |
| `MagiskBean` / `Magisk.*` references | unambiguous |
| `loadLibrary("foo")` where `libfoo.so` imports `mount`/`ptrace`/`setuid` | ambiguous (depends on actual usage) |
| Path string `/system/xbin/su` | unambiguous |
| String `"su"` in `.c`/`.cpp` source passed to `exec*()` family | unambiguous |

### 7. Emit findings.json

Aggregate everything into the standard Findings JSON shape. Same schema as APK pipeline.

## Edge cases

- **Monorepos with multiple sub-projects**: scan each sub-project independently and merge signals. Tag each signal with `source: "repo:<subproject>/<file>:<line>"`.
- **Generated code** (e.g. protobuf-generated `*.pb.cc`): the source paths will be `*.pb.cc` or `*.gen.java`. Treat as normal source — the generated code is part of the binary's behavior.
- **Vendored dependencies** (`vendor/`, `third_party/`): include them in the scan — they contribute to the binary's actual syscall surface. But tag with `source: "repo:vendor/..."` so they're distinguishable.
- **Build-time-only code** (e.g. `build/`, `scripts/`): skip these directories — they don't run on the device.
- **`#ifdef` blocks**: matches inside `#ifdef DEBUG` should be tagged `confidence: "ambiguous"` with `evidence: "inside #ifdef DEBUG"`.
- **Test code** (`*_test.go`, `*Test.java`, `tests/`): skip — test syscalls don't ship in the production binary.

## Output (findings.json shape)

```json
{
  "target": "/path/to/repo",
  "target_type": "repo",
  "project_type": "android-gradle",
  "package_name": "com.example.foo",
  "version_name": "1.2.3",
  "version_code": 123,
  "manifest_path": "app/src/main/AndroidManifest.xml",
  "signals": [
    {
      "kind": "android_perm",
      "name": "INTERNET",
      "source": "repo:app/src/main/AndroidManifest.xml:5",
      "evidence": "<uses-permission android:name=\"android.permission.INTERNET\" />",
      "confidence": "unambiguous"
    },
    {
      "kind": "syscall",
      "name": "ptrace",
      "source": "repo:app/src/main/cpp/native.c:42",
      "evidence": "ptrace(PTRACE_ATTACH, pid, NULL, NULL);",
      "confidence": "unambiguous"
    },
    {
      "kind": "su_invocation",
      "name": "Runtime.exec(\"su\")",
      "source": "repo:app/src/main/java/com/example/RootHelper.java:15",
      "evidence": "Runtime.getRuntime().exec(\"su\");",
      "confidence": "unambiguous"
    }
  ]
}
```
