# Syscall → Capability / Group mapping table

This is the authoritative mapping used by all pipelines (apk, binary, repo, strace). When a pipeline finds a signal, it looks up the signal in this table to determine which capabilities and/or groups to add to the Profile.

**Format**: each entry has the signal kind, the signal name (regex or string match), the capabilities to add, the groups to add (Android GIDs as integers), the confidence level (`unambiguous` or `ambiguous`), and notes.

## Confidence levels

- **`unambiguous`**: the signal directly implies the capability. Add it in Pass 1.
- **`ambiguous`**: the signal *suggests* the capability but doesn't prove it. Defer to the user in Pass 2 (ambiguous-findings section of `analysis.md`).

## Syscalls (C / JNI / strace)

| Signal | Caps | Groups | Confidence | Notes |
|---|---|---|---|---|
| `bind()` to port < 1024 (AF_INET/AF_INET6) | `CAP_NET_BIND_SERVICE` | — | unambiguous | strace shows `bind(fd, {sa_family=AF_INET, sin_port=htons(N)}, ...)` with N < 1024 |
| `socket(AF_PACKET, SOCK_RAW, …)` | `CAP_NET_RAW` | `3004` | unambiguous | packet capture (tcpdump-like) |
| `socket(AF_INET, SOCK_RAW, …)` | `CAP_NET_RAW` | `3004` | unambiguous | raw IP socket |
| `socket(AF_INET6, SOCK_RAW, …)` | `CAP_NET_RAW` | `3004` | unambiguous | raw IPv6 socket |
| `setsockopt(SO_DEBUG)` | `CAP_NET_ADMIN` | `3005` | unambiguous | |
| `setsockopt(SO_MARK)` | `CAP_NET_ADMIN` | `3005` | unambiguous | firewall mark |
| `setsockopt(SO_PRIORITY)` w/ prio outside 0-6 | `CAP_NET_ADMIN` | `3005` | unambiguous | |
| `setsockopt(SO_RCVBUFFORCE\|SO_SNDBUFFORCE)` | `CAP_NET_ADMIN` | `3005` | unambiguous | |
| `mount(2)` / `umount2` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `pivot_root` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `swapon` / `swapoff` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `sethostname` / `setdomainname` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `quotactl` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `setns(CLONE_NEWNS\|NEWPID\|NEWNET\|NEWIPC\|NEWUTS)` | `CAP_SYS_ADMIN` | — | unambiguous | (NEWUSER doesn't need cap) |
| `clone(CLONE_NEWNS\|NEWPID\|NEWNET\|NEWIPC\|NEWUTS)` | `CAP_SYS_ADMIN` | — | unambiguous | (NEWUSER doesn't need cap) |
| `fanotify_init` | `CAP_SYS_ADMIN` | — | unambiguous | |
| `setxattr("security.*", …)` | `CAP_SYS_ADMIN` | — | unambiguous | security xattrs |
| `chroot` | `CAP_SYS_CHROOT` | — | unambiguous | |
| `setuid` / `setreuid` / `setresuid` / `setfsuid` | `CAP_SETUID` | — | unambiguous | |
| `setgid` / `setregid` / `setresgid` / `setfsgid` / `setgroups` | `CAP_SETGID` | — | unambiguous | |
| `ptrace` | `CAP_SYS_PTRACE` | — | unambiguous | |
| `process_vm_readv` / `process_vm_writev` | `CAP_SYS_PTRACE` | — | unambiguous | |
| `kcmp` | `CAP_SYS_PTRACE` | — | unambiguous | |
| open `/proc/<pid>/maps` or `/proc/<pid>/mem` (not own pid) | `CAP_SYS_PTRACE` | — | unambiguous | |
| readlink `/proc/<pid>/exe` / `/proc/<pid>/fd/*` (not own pid) | `CAP_SYS_PTRACE` | — | unambiguous | |
| `mknod` / `mknodat` | `CAP_MKNOD` | — | unambiguous | |
| `reboot` / `kexec_load` / `kexec_file_load` | `CAP_SYS_BOOT` | — | unambiguous | |
| `init_module` / `finit_module` / `delete_module` | `CAP_SYS_MODULE` | — | unambiguous | |
| `iopl` / `ioperm` | `CAP_SYS_RAWIO` | — | unambiguous | |
| open `/proc/kcore` / `/dev/mem` / `/dev/kmem` | `CAP_SYS_RAWIO` | — | unambiguous | |
| `ioctl FIBMAP` | `CAP_SYS_RAWIO` | — | unambiguous | |
| `msr` device (x86 model-specific registers) | `CAP_SYS_RAWIO` | — | unambiguous | |
| `settimeofday` / `stime` / `adjtimex` | `CAP_SYS_TIME` | — | unambiguous | |
| `clock_settime(CLOCK_REALTIME)` | `CAP_SYS_TIME` | — | unambiguous | |
| `vhangup` | `CAP_SYS_TTY_CONFIG` | — | unambiguous | |
| `ioctl TIOCSTI` (on non-controlling tty) | `CAP_SYS_TTY_CONFIG` (also `CAP_SYS_ADMIN`) | — | unambiguous | |
| `acct` | `CAP_SYS_PACCT` | — | unambiguous | |
| `syslog` privileged ops (klogctl actions) | `CAP_SYSLOG` | — | unambiguous | |
| `nice` / `setpriority` on other processes | `CAP_SYS_NICE` | — | unambiguous | |
| `sched_setscheduler` / `sched_setattr` on other procs | `CAP_SYS_NICE` | — | unambiguous | |
| `sched_setaffinity` on other procs | `CAP_SYS_NICE` | — | unambiguous | |
| `ioprio_set(IOPRIO_CLASS_RT)` | `CAP_SYS_ADMIN` (also `CAP_SYS_NICE`) | — | unambiguous | |
| `migrate_pages` / `move_pages` on other procs | `CAP_SYS_NICE` | — | unambiguous | |
| `setrlimit` / `prlimit` raising limits | `CAP_SYS_RESOURCE` | — | unambiguous | |
| `prctl(PR_SET_MM, …)` | `CAP_SYS_RESOURCE` | — | unambiguous | |
| `mlock` / `mlockall` / `mlock2` / `mmap(MAP_LOCKED)` | `CAP_IPC_LOCK` | — | unambiguous | |
| `shmctl(SHM_LOCK)` | `CAP_IPC_LOCK` | — | unambiguous | |
| `kill` / `tgkill` / `tkill` / `pidfd_send_signal` (to other uid) | `CAP_KILL` | — | unambiguous | |
| `chown` / `fchown` / `lchown` / `fchownat` (arbitrary) | `CAP_CHOWN` | — | unambiguous | |
| `chmod` / `fchmod` / `fchmodat` (on others' files) | `CAP_FOWNER` | — | unambiguous | (sometimes also `CAP_FSETID`) |
| `utime` / `utimes` / `utimensat` (on others' files) | `CAP_FOWNER` | — | unambiguous | |
| `fcntl(F_SETLEASE)` | `CAP_LEASE` | — | unambiguous | |
| `ioctl FS_IOC_SETFLAGS` w/ `FS_APPEND_FL`/`FS_IMMUTABLE_FL` | `CAP_LINUX_IMMUTABLE` | — | unambiguous | chattr +i/+a |
| `setxattr("security.capability", …)` / `setcap` | `CAP_SETFCAP` | — | unambiguous | |
| `capset` | `CAP_SETPCAP` | — | unambiguous | |
| `prctl(PR_CAPBSET_DROP)` | `CAP_SETPCAP` | — | unambiguous | |
| `bpf(BPF_*`, …) | `CAP_BPF` (and `CAP_SYS_ADMIN` on kernel < 5.8) | — | unambiguous | since Linux 5.8 |
| `perf_event_open` | `CAP_PERFMON` (and `CAP_SYS_ADMIN` on kernel < 5.8) | — | unambiguous | since Linux 5.8 |
| `clone3` w/ `set_tid` | `CAP_CHECKPOINT_RESTORE` | — | unambiguous | since Linux 5.9 |
| readlink `/proc/<pid>/map_files` (not own pid) | `CAP_CHECKPOINT_RESTORE` | — | unambiguous | since Linux 5.9 |
| `timerfd_create(CLOCK_REALTIME_ALARM\|CLOCK_BOOTTIME_ALARM)` | `CAP_WAKE_ALARM` | — | unambiguous | |
| `epoll` w/ `EPOLLWAKEUP` | `CAP_BLOCK_SUSPEND` | — | unambiguous | |
| write to `/proc/sys/wake_lock` | `CAP_BLOCK_SUSPEND` | — | unambiguous | |
| `socket(AF_NETLINK, …, NETLINK_AUDIT)` for read | `CAP_AUDIT_READ` | — | unambiguous | |
| libaudit `audit_set_pid` / `audit_log_acct_message` | `CAP_AUDIT_WRITE` | — | unambiguous | |
| libaudit `audit_set_*` / `audit_rule_*` | `CAP_AUDIT_CONTROL` | — | unambiguous | |
| `setxattr("security.SMACK*", …)` | `CAP_MAC_ADMIN` (config) / `CAP_MAC_OVERRIDE` (override) | — | ambiguous | Smack-specific; rare on Android |
| `linkat(…, AT_EMPTY_PATH)` | `CAP_DAC_READ_SEARCH` | — | unambiguous | |
| `open_by_handle_at` | `CAP_DAC_READ_SEARCH` | — | unambiguous | |

## Imported libc symbols (binary pipeline)

When the binary pipeline sees these as imported dynamic symbols, treat as syscall signals above. Confidence is `unambiguous` for direct syscall wrappers (`mount`, `setuid`, etc.) and `ambiguous` for indirect helpers (e.g. `getpwnam` may or may not call `setuid` downstream — depends on context).

| Symbol | Caps | Confidence | Notes |
|---|---|---|---|
| `mount` / `umount` / `umount2` | `CAP_SYS_ADMIN` | unambiguous | |
| `pivot_root` | `CAP_SYS_ADMIN` | unambiguous | |
| `setuid` / `seteuid` / `setresuid` / `setreuid` / `setfsuid` | `CAP_SETUID` | unambiguous | |
| `setgid` / `setegid` / `setresgid` / `setregid` / `setfsgid` / `setgroups` | `CAP_SETGID` | unambiguous | |
| `chroot` | `CAP_SYS_CHROOT` | unambiguous | |
| `ptrace` | `CAP_SYS_PTRACE` | unambiguous | |
| `process_vm_readv` / `process_vm_writev` | `CAP_SYS_PTRACE` | unambiguous | |
| `kcmp` | `CAP_SYS_PTRACE` | unambiguous | |
| `mknod` / `mknodat` | `CAP_MKNOD` | unambiguous | |
| `reboot` / `kexec_load` / `kexec_file_load` | `CAP_SYS_BOOT` | unambiguous | |
| `init_module` / `finit_module` / `delete_module` | `CAP_SYS_MODULE` | unambiguous | |
| `iopl` / `ioperm` | `CAP_SYS_RAWIO` | unambiguous | |
| `settimeofday` / `stime` / `adjtimex` | `CAP_SYS_TIME` | unambiguous | |
| `vhangup` | `CAP_SYS_TTY_CONFIG` | unambiguous | |
| `acct` | `CAP_SYS_PACCT` | unambiguous | |
| `swapon` / `swapoff` | `CAP_SYS_ADMIN` | unambiguous | |
| `sethostname` / `setdomainname` | `CAP_SYS_ADMIN` | unambiguous | |
| `quotactl` | `CAP_SYS_ADMIN` | unambiguous | |
| `setns` | `CAP_SYS_ADMIN` | unambiguous | |
| `fanotify_init` | `CAP_SYS_ADMIN` | unambiguous | |
| `bpf` | `CAP_BPF` | unambiguous | |
| `perf_event_open` | `CAP_PERFMON` | unambiguous | |
| `clone3` (with `set_tid`) | `CAP_CHECKPOINT_RESTORE` | unambiguous | |
| `setcap` / `cap_set_file` / `cap_set_fd` | `CAP_SETFCAP` | unambiguous | |
| `capset` | `CAP_SETPCAP` | unambiguous | |
| `setxattr` / `lsetxattr` / `fsetxattr` (with `security.capability`) | `CAP_SETFCAP` | unambiguous | |
| `setxattr` / `lsetxattr` / `fsetxattr` (with `security.*`) | `CAP_SYS_ADMIN` | ambiguous | depends on the attribute name |
| `setrlimit` / `prlimit` | `CAP_SYS_RESOURCE` | ambiguous | raising limits needs cap; lowering doesn't |
| `mlock` / `mlockall` / `mlock2` | `CAP_IPC_LOCK` | unambiguous | |
| `kill` / `tgkill` / `tkill` / `pidfd_send_signal` | `CAP_KILL` | ambiguous | only if target is different uid |
| `chown` / `fchown` / `lchown` / `fchownat` | `CAP_CHOWN` | ambiguous | only if arbitrary (not matching caller uid) |
| `chmod` / `fchmod` / `fchmodat` | `CAP_FOWNER` | ambiguous | only on others' files |
| `utime` / `utimes` / `utimensat` | `CAP_FOWNER` | ambiguous | only on others' files |
| `fcntl` (with `F_SETLEASE`) | `CAP_LEASE` | unambiguous | |
| `ioctl` (with `FS_IOC_SETFLAGS` + `FS_APPEND_FL`/`FS_IMMUTABLE_FL`) | `CAP_LINUX_IMMUTABLE` | unambiguous | |
| `timerfd_create` (with `CLOCK_REALTIME_ALARM` / `CLOCK_BOOTTIME_ALARM`) | `CAP_WAKE_ALARM` | unambiguous | |
| `socket` + `setsockopt(SO_BROADCAST)` | `CAP_NET_BROADCAST` | ambiguous | rarely actually needed |
| `socket(AF_PACKET, …)` | `CAP_NET_RAW` + group 3004 | unambiguous | |
| `socket(AF_INET/AF_INET6, SOCK_RAW, …)` | `CAP_NET_RAW` + group 3004 | unambiguous | |
| `nice` / `setpriority` | `CAP_SYS_NICE` | ambiguous | only if targeting other procs |

## AndroidManifest permissions (APK pipeline)

| Android permission | Caps | Groups | Confidence | Notes |
|---|---|---|---|---|
| `INTERNET` | — | `3003` (inet) | unambiguous | |
| `ACCESS_NETWORK_STATE` | — | — | unambiguous | no group needed (capget) |
| `CHANGE_NETWORK_STATE` | `CAP_NET_ADMIN` | `3005` | unambiguous | |
| `ACCESS_WIFI_STATE` | — | — | unambiguous | no cap/group needed for state read |
| `CHANGE_WIFI_STATE` | `CAP_NET_ADMIN` | `3005` | unambiguous | |
| `CHANGE_WIFI_MULTICAST_STATE` | — | `3005` | unambiguous | |
| `BLUETOOTH` | — | `3002` | unambiguous | |
| `BLUETOOTH_ADMIN` | — | `3001` | unambiguous | |
| `ACCESS_FINE_LOCATION` | — | (system gps 1021 — not granted to userland) | unambiguous | userland doesn't get the gps group; capability not needed |
| `ACCESS_COARSE_LOCATION` | — | — | unambiguous | |
| `CAMERA` | — | (system camera 1006 — not granted to userland) | unambiguous | |
| `RECORD_AUDIO` | — | (system audio 1005 — not granted to userland) | unambiguous | |
| `READ_EXTERNAL_STORAGE` | — | `1028` | unambiguous | |
| `WRITE_EXTERNAL_STORAGE` | — | `1015`, `1023` | unambiguous | |
| `MANAGE_EXTERNAL_STORAGE` | — | `1077` | unambiguous | full external storage access |
| `READ_MEDIA_AUDIO` / `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` | — | (system media_* — not granted) | unambiguous | |
| `MOUNT_UNMOUNT_FILESYSTEMS` | `CAP_SYS_ADMIN` | `1009` | unambiguous | system-only permission |
| `WAKE_LOCK` | — | `3010` | unambiguous | |
| `VIBRATE` | — | — | unambiguous | no group |
| `DUMP` | — | `1007` (log), `1036` (logd) | unambiguous | |
| `READ_LOGS` | — | `1007` | unambiguous | |
| `SET_TIME` | `CAP_SYS_TIME` | — | unambiguous | |
| `SET_TIME_ZONE` | `CAP_SYS_TIME` | — | ambiguous | timezone is not always cap-gated |
| `REQUEST_INSTALL_PACKAGES` | — | `1012` | ambiguous | install group is system-only usually |
| `QUERY_ALL_PACKAGES` | — | `1032` | ambiguous | package_info group is system-only usually |
| `NFC` | — | `1027` | unambiguous | |
| `READ_PROC` (rare) | — | `3009` | unambiguous | |
| `ACCESS_MTP` | — | `1024` | unambiguous | MTP USB driver |
| `USB_PERMISSION` (custom) | — | `1018` | ambiguous | USB devices group |

## Java / Kotlin source signals (repo + APK smali)

| Signal | Caps | Groups | Confidence | Notes |
|---|---|---|---|---|
| `Runtime.exec("su")` / `Runtime.exec(new String[]{"su", ...})` | (sets `allowSu=true`) | — | unambiguous | the user asked to grant root — this confirms intent |
| `ProcessBuilder("su")` / `ProcessBuilder().command("su")` | (sets `allowSu=true`) | — | unambiguous | |
| libsu `Shell.su(...)` / `Shell.cmd(...).exec()` (with root=true) | (sets `allowSu=true`) | — | unambiguous | com.topjohnwu.superuser |
| `MagiskBean` / `Magisk.execute("...")` | (sets `allowSu=true`) | — | unambiguous | |
| `RootCommands.*` | (sets `allowSu=true`) | — | ambiguous | depends on usage |
| `new ServerSocket(port)` with port < 1024 | `CAP_NET_BIND_SERVICE` | — | unambiguous | |
| `new DatagramSocket(port)` with port < 1024 | `CAP_NET_BIND_SERVICE` | — | unambiguous | |
| `NetworkInterface.getByName(...)` (read) | — | — | unambiguous | no special group |
| `NetworkInterface.getNetworkInterfaces()` then `setter` | `CAP_NET_ADMIN` | `3005` | ambiguous | only if modifying |
| `InetAddress` resolution (no group) | — | — | unambiguous | uses libc, no special group |
| `Files.setPosixFilePermissions` on others' files | `CAP_FOWNER` | — | ambiguous | |
| `Files.setAttribute("unix:*")` | `CAP_FOWNER` | — | ambiguous | |
| `File("/dev/...")` write | (depends on device) | — | ambiguous | see device table below |
| `File("/dev/mem")` or `File("/dev/kmem")` | `CAP_SYS_RAWIO` | — | unambiguous | |
| `File("/dev/uhid")` | — | `3011` | unambiguous | uhid group |
| `File("/proc/<pid>/maps").readText()` (other pid) | `CAP_SYS_PTRACE` | — | unambiguous | |
| `File("/proc/<pid>/mem")` | `CAP_SYS_PTRACE` | — | unambiguous | |
| `File("/proc/kcore")` | `CAP_SYS_RAWIO` | — | unambiguous | |
| `File("/sys/kernel/tracing/...")` | `CAP_SYS_ADMIN` (+ CAP_PERFMON on 5.8+) | `3012` (readtracefs) | ambiguous | tracefs |
| `File("/data/adb/...")` | (sets `allowSu=true`) + `CAP_DAC_READ_SEARCH` | — | unambiguous | KSU internal paths imply root intent |

## JNI / native code declarations (repo + APK)

| Signal | Treatment | Notes |
|---|---|---|
| `extern "C" JNIEXPORT ... mount(...)` | Look up the symbol in binary pipeline | recurse into native analysis |
| `System.loadLibrary("foo")` | Find `libfoo.so` in `lib/<abi>/`, run binary pipeline | recurse |
| `native int ptrace(int, int, ...)` declared | `CAP_SYS_PTRACE` | unambiguous |
| `native int setuid(int)` declared | `CAP_SETUID` | unambiguous |

## Device nodes (file path signals)

The PATH_MAP below is consulted for BOTH:
- `openat(path, ...)` calls (the path is the first arg)
- `write(fd<path>, ...)` / `read(fd<path>, ...)` calls (the path is in the strace `-y` fd annotation)

So adding an entry here covers BOTH the open and the write/read cases.

| Path | Caps | Notes |
|---|---|---|
| `/dev/mem`, `/dev/kmem` | `CAP_SYS_RAWIO` | |
| `/proc/kcore` | `CAP_SYS_RAWIO` | |
| `/dev/uhid` | group `3011` (uhid) | |
| `/dev/dm-*` | `CAP_SYS_ADMIN` | device-mapper |
| `/dev/block/*` | `CAP_SYS_RAWIO` (or `CAP_SYS_ADMIN` for some ioctls) | |
| `/dev/loop*` | `CAP_SYS_ADMIN` | |
| `/sys/kernel/debug/` | `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH` | debugfs |
| `/sys/kernel/tracing/` | `CAP_SYS_ADMIN` + `CAP_PERFMON` + group `3012` (readtracefs) | tracefs |
| `/proc/self/*` | (none — own process) | |
| `/proc/<other_pid>/...` | `CAP_SYS_PTRACE` | |
| `/data/adb/ksu/*` | `CAP_DAC_READ_SEARCH` + (sets `allowSu=true`) | KSU internal |
| `/data/adb/modules/*` | `CAP_DAC_READ_SEARCH` + (sets `allowSu=true`) | KSU module storage |
| `/system/xbin/su`, `/system/bin/su` | (sets `allowSu=true`) | root intent |
| `/sbin/su`, `/system/sbin/su` | (sets `allowSu=true`) | root intent |
| `/dev/socket/*` | (depends on socket — usually system group) | |

## File descriptor I/O syscalls (write / read / pwrite / pread / writev / readv)

These syscalls are special: **the syscall name itself doesn't imply any capability** — what matters is the **path the fd points to**, which is only available in strace output if the user runs strace with the **`-y` flag** (which prints the file path next to each fd number).

Without `-y`, strace prints `write(3, "...", 4)` — the fd number alone is useless. With `-y`, strace prints `write(3</sys/kernel/config/usb_gadget/g1/UDC>, "...", 4)` — the path annotation lets us map the call to capabilities.

The strace_capture.sh helper now always passes `-y`. The strace_analyze.py parser has a special handler that extracts the path from the `-y` annotation and consults the same PATH_MAP as the openat handler.

### Privileged write targets (the "configfs / sysfs / dev" pattern)

On Android, many configfs / sysfs / dev paths are owned by `system:system` with mode `0660`. The app's UID (e.g. `10000+`) is **not** in the `system` group, so a `write()` to such a path returns `EACCES` — even for root. The fix is `CAP_DAC_OVERRIDE`, which bypasses file permission checks entirely.

This pattern is the classic "USB gadget rebind" failure:

| Path | Caps | Notes |
|---|---|---|
| `/sys/kernel/config/usb_gadget/*` | `CAP_DAC_OVERRIDE` + `CAP_DAC_READ_SEARCH` | USB gadget configfs — writing `<controller>` to `<gadget>/UDC` binds it; writing `""` unbinds. Files are `system:system` mode 0660. |
| `/sys/kernel/config/*` (other) | `CAP_DAC_OVERRIDE` + `CAP_DAC_READ_SEARCH` | Other configfs subtrees (e.g. USB Type-C, NFS, binderfs) |
| `/sys/class/*` | `CAP_DAC_OVERRIDE` | sysfs class nodes (often `system:system` mode 0644 / 0660) |
| `/sys/devices/*` | `CAP_DAC_OVERRIDE` | sysfs device nodes |
| `/dev/hidg*` | `CAP_DAC_OVERRIDE` + `CAP_FOWNER` | USB HID gadget device nodes (functionfs / hidg) |
| `/dev/usb/*` | `CAP_DAC_OVERRIDE` | USB device access |
| `/dev/input/*` | `CAP_DAC_OVERRIDE` | input device nodes (touchscreen, keyboard) |
| `/dev/socket/*` | `CAP_DAC_OVERRIDE` | Android system sockets (often `system:system` mode 0660) |
| `/proc/sys/*` | `CAP_SYS_ADMIN` + `CAP_DAC_OVERRIDE` | kernel tunables (`/proc/sys/kernel/*`, `/proc/sys/net/*`, etc.) |
| `/sys/module/*` | `CAP_SYS_ADMIN` + `CAP_DAC_OVERRIDE` | module parameters (`/sys/module/<mod>/parameters/*`) |

### Why `openat()` alone is NOT enough

A common bug pattern (the one the user hit): the app does

```c
int fd = openat("/sys/kernel/config/usb_gadget/g1/UDC", O_WRONLY);  // ✅ succeeds (just opens)
write(fd, "", 0);                                                   // ❌ EACCES without CAP_DAC_OVERRIDE
```

If the strace filter only captures `openat()` (the `%file` category) but NOT `write()` (which is in the `%desc` category), the strace shows `openat → ✅ success` and looks fine. But the actual privilege failure on the subsequent `write()` is invisible.

**The fix is two-fold** (both applied in this skill version):
1. `strace_capture.sh` now uses `-e trace=%file,%desc,%network,%process,%signal,%memory,%ipc` (added `%desc`).
2. `strace_capture.sh` now always passes `-y` so the fd→path annotation is preserved.

With both fixes, the `write(3</sys/.../g1/UDC>, "", 0) = -1 EACCES` line is captured AND can be mapped to `CAP_DAC_OVERRIDE`.

### Downstream symptoms of upstream `write()` EACCES failures

When `write()` to a configfs / dev node returns `EACCES`, the failure is often **silent** — the syscall returns the error code, but the calling binary may not check it, or may log it at debug level only. The downstream symptom is then a *different* error code on a *later* syscall that looks unrelated:

| Upstream failure | Downstream symptom | Why |
|---|---|---|
| `write("/sys/.../g1/UDC", "") = -1 EACCES` (unbind g1) | `write("/sys/.../usb_arsenal/UDC", "...") = -1 EBUSY` (bind new gadget) | g1 still holds the USB controller, so the new bind fails with "Device or resource busy" |
| `write("/dev/hidg0", "") = -1 EACCES` (set up HID report descriptor) | `write("/dev/hidg0", report) = -1 EPIPE` (write HID report) | device not configured, write fails |
| `write("/sys/class/.../enable", "1") = -1 EACCES` (enable a feature) | subsequent reads of `/sys/class/.../state` return stale data | feature never enabled |

The skill flags these upstream `write()` EACCES signals so the user can root-cause the actual problem rather than chasing downstream symptoms.

## Recommended set (added in `recommended` mode)

| Cap | Why added in `recommended` mode |
|---|---|
| `CAP_DAC_READ_SEARCH` | Lets the confined app `ls` / read protected paths — same privileges as a shell user. Useful for debugging tools, file managers, log viewers. |
| `CAP_KILL` | Lets the app cleanly signal child processes (e.g. shell wrappers, server supervisors) without leaving zombies. |
| `CAP_SYS_RESOURCE` | Lets the app override RLIMIT_NOFILE etc. — useful for fork-heavy tools to avoid spurious EAGAIN on `accept()` / `open()`. |

These three are the canonical "convenience" set and the user explicitly opts in via `recommended` mode.
