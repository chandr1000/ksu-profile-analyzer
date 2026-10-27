# Linux capabilities (KernelSU `Capabilities.kt`)

Verbatim from `manager/app/src/main/java/.../profile/Capabilities.kt`. All three KSU-family forks currently ship the **same** 40-entry table.

**Source files** (canonical, current as of last refresh):

- upstream: <https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt>
- KSU-Next: <https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt>
- SukiSU-Ultra: <https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Capabilities.kt>

## Canonical table

| # | Constant | Display | Description | Detection hint |
|---|---|---|---|---|
| 0 | `CAP_CHOWN` | CHOWN | Make arbitrary changes to file UIDs and GIDs (see `chown(2)`) | `chown`, `fchown`, `lchown`, `fchownat` calls |
| 1 | `CAP_DAC_OVERRIDE` | DAC_OVERRIDE | Bypass file read, write, and execute permission checks | bypass of `rwx` mode bits (rare explicit signal; usually implied by other caps) |
| 2 | `CAP_DAC_READ_SEARCH` | DAC_READ_SEARCH | Bypass file read permission checks and directory read and execute permission checks | `openat("*" \| O_RDONLY)` on protected paths, `open_by_handle_at`, `linkat(…, AT_EMPTY_PATH)` |
| 3 | `CAP_FOWNER` | FOWNER | Bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file (e.g. `chmod(2)`, `utime(2)`), excluding those covered by `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` | `chmod`, `fchmod`, `fchmodat`, `utime`, `utimes`, `utimensat`, `setxattr` on `user.*`, `O_NOATIME` on arbitrary files |
| 4 | `CAP_FSETID` | FSETID | Don't clear set-user-ID and set-group-ID permission bits when a file is modified; set the set-group-ID bit for a file whose GID does not match the filesystem or any of the supplementary GIDs of the calling process | `chmod`/`fchmod` preserving SUID/SGID bits |
| 5 | `CAP_KILL` | KILL | Bypass permission checks for sending signals (see `kill(2)`) | `kill`, `tgkill`, `tkill`, `pidfd_send_signal` to non-owned processes |
| 6 | `CAP_SETGID` | SETGID | Make arbitrary manipulations of process GIDs and supplementary GID list; allow `setgid(2)` manipulation of the caller's effective and real group IDs | `setgid`, `setegid`, `setresgid`, `setregid`, `setfsgid`, `setgroups` |
| 7 | `CAP_SETUID` | SETUID | Make arbitrary manipulations of process UIDs (`setuid(2)`, `setreuid(2)`, `setresuid(2)`, `setfsuid(2)`) | `setuid`, `seteuid`, `setresuid`, `setreuid`, `setfsuid` |
| 8 | `CAP_SETPCAP` | SETPCAP | If file capabilities are supported: grant or remove any capability in the caller's permitted capability set to or from any other process | `capset`, `prctl(PR_CAPBSET_DROP)` |
| 9 | `CAP_LINUX_IMMUTABLE` | LINUX_IMMUTABLE | Set the `FS_APPEND_FL` and `FS_IMMUTABLE_FL` inode flags (see `chattr(1)`) | `ioctl FS_IOC_SETFLAGS` with `FS_APPEND_FL` / `FS_IMMUTABLE_FL` |
| 10 | `CAP_NET_BIND_SERVICE` | NET_BIND_SERVICE | Bind a socket to Internet domain privileged ports | `bind()` to port < 1024 (AF_INET / AF_INET6) |
| 11 | `CAP_NET_BROADCAST` | NET_BROADCAST | Make socket broadcasts, and listen to multicasts | `setsockopt(SO_BROADCAST)` (largely unused in practice) |
| 12 | `CAP_NET_ADMIN` | NET_ADMIN | Perform various network-related operations: interface configuration, administration of IP firewall, masquerading, and accounting, modify routing tables, bind to any address for transparent proxying, set type-of-service (TOS), clear driver statistics, set promiscuous mode, enabling multicasting, use `setsockopt(2)` to set the following socket options: SO_DEBUG, SO_MARK, SO_PRIORITY (for a priority outside the range 0 to 6), SO_RCVBUFFORCE, and SO_SNDBUFFORCE | `ioctl SIOC*` net ifconfig ops, `setsockopt(SO_MARK\|SO_PRIORITY\|SO_RCVBUFFORCE\|SO_SNDBUFFORCE\|SO_DEBUG)` |
| 13 | `CAP_NET_RAW` | NET_RAW | Use RAW and PACKET sockets | `socket(AF_PACKET, SOCK_RAW, …)`, `socket(AF_INET, SOCK_RAW, …)`, `socket(AF_INET6, SOCK_RAW, …)` |
| 14 | `CAP_IPC_LOCK` | IPC_LOCK | Lock memory (`mlock(2)`, `mlockall(2)`, `mmap(2)`, `shmctl(2)`) | `mlock`, `mlockall`, `mlock2`, `shmctl(SHM_LOCK)`, `mmap(MAP_LOCKED)` |
| 15 | `CAP_IPC_OWNER` | IPC_OWNER | Bypass permission checks for operations on System V IPC objects | `msgget`/`semget`/`shmget` on objects owned by other users |
| 16 | `CAP_SYS_MODULE` | SYS_MODULE | Load and unload kernel modules (see `init_module(2)` and `delete_module(2)`) | `init_module`, `finit_module`, `delete_module`, modprobe/kmod library calls |
| 17 | `CAP_SYS_RAWIO` | SYS_RAWIO | Perform I/O port operations (`iopl(2)` and `ioperm(2)`); access `/proc/kcore` | `iopl`, `ioperm`, open `/proc/kcore`, `/dev/mem`, `/dev/kmem`, `ioctl FIBMAP`, `msr` device |
| 18 | `CAP_SYS_CHROOT` | SYS_CHROOT | Use `chroot(2)` | `chroot`, `setns(CLONE_NEWNS)` (also implies SYS_ADMIN) |
| 19 | `CAP_SYS_PTRACE` | SYS_PTRACE | Trace arbitrary processes using `ptrace(2)` | `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, open `/proc/<pid>/{maps,mem,exe}`, readlink `/proc/<pid>/fd/*` |
| 20 | `CAP_SYS_PACCT` | SYS_PACCT | Use `acct(2)` | `acct` |
| 21 | `CAP_SYS_ADMIN` | SYS_ADMIN | The "new root" — overloaded. See Notes below. | `mount`, `umount`, `umount2`, `pivot_root`, `swapon`, `swapoff`, `sethostname`, `setdomainname`, `quotactl`, `setns`, `clone(CLONE_NEWNS\|NEWPID\|NEWNET\|NEWIPC\|NEWUTS\|NEWUSER)`, `fanotify_init`, `setxattr` on `security.*`, privileged `syslog` ops, `madvise(MADV_HWPOISON)`, `ioctl TIOCSTI` |
| 22 | `CAP_SYS_BOOT` | SYS_BOOT | Use `reboot(2)` and `kexec_load(2)`, reboot and load a new kernel for later execution | `reboot`, `kexec_load`, `kexec_file_load` |
| 23 | `CAP_SYS_NICE` | SYS_NICE | Raise process nice value (`nice(2)`, `setpriority(2)`) and change the nice value for arbitrary processes; set real-time scheduling policies for calling process, and set scheduling policies and priorities for arbitrary processes (`sched_setscheduler(2)`, `sched_setparam(2)`) | `nice`, `setpriority`, `sched_setscheduler`, `sched_setattr`, `sched_setaffinity`, `ioprio_set(IOPRIO_CLASS_RT)`, `migrate_pages`, `move_pages` |
| 24 | `CAP_SYS_RESOURCE` | SYS_RESOURCE | Override resource Limits. Set resource limits (`setrlimit(2)`, `prlimit(2)`), override quota limits (`quota(2)`, `quotactl(2)`), override reserved space on ext2 filesystem (`ext2_ioctl(2)`), override size restrictions on IPC message queues (`msg(2)`) and system V shared memory segments (`shmget(2)`), and override the `/proc/sys/fs/pipe-size-max` limit | `setrlimit`, `prlimit`, `prctl(PR_SET_MM)`, ext2 ioctl journaling, write to `/proc/<pid>/oom_score_adj` lowering it |
| 25 | `CAP_SYS_TIME` | SYS_TIME | Set system clock (`settimeofday(2)`, `stime(2)`, `adjtimex(2)`); set real-time (hardware) clock | `settimeofday`, `stime`, `adjtimex`, `clock_settime(CLOCK_REALTIME)`, `/dev/rtc` writes |
| 26 | `CAP_SYS_TTY_CONFIG` | SYS_TTY_CONFIG | Use `vhangup(2)`; employ various privileged `ioctl(2)` operations on virtual terminals | `vhangup`, `ioctl KD*`/`VT_*`/`TIOCSTI` on VTs |
| 27 | `CAP_MKNOD` | MKNOD | Create special files using `mknod(2)` | `mknod`, `mknodat` |
| 28 | `CAP_LEASE` | LEASE | Establish leases on arbitrary files (see `fcntl(2)`) | `fcntl(F_SETLEASE)` |
| 29 | `CAP_AUDIT_WRITE` | AUDIT_WRITE | Write records to kernel auditing log | `audit_set_pid`, `audit_log_acct_message` (libaudit) |
| 30 | `CAP_AUDIT_CONTROL` | AUDIT_CONTROL | Enable and disable kernel auditing; change auditing filter rules; retrieve auditing status and filtering rules | libaudit `audit_set_*`, `audit_rule_*(…)` |
| 31 | `CAP_SETFCAP` | SETFCAP | If file capabilities are supported: grant or remove any capability in any capability set to any file | `setcap`, `cap_set_file`, `setxattr("security.capability", …)` |
| 32 | `CAP_MAC_OVERRIDE` | MAC_OVERRIDE | Override Mandatory Access Control (MAC). Implemented for the Smack Linux Security Module (LSM) | Smack-related `setxattr` on `security.SMACK*` |
| 33 | `CAP_MAC_ADMIN` | MAC_ADMIN | Allow MAC configuration or state changes. Implemented for the Smack LSM | Smack-related config writes |
| 34 | `CAP_SYSLOG` | SYSLOG | Perform privileged `syslog(2)` operations | `syslog` action `SYSLOG_ACTION_*` privileged ones, `/proc/sys/kernel/kptr_restrict` reads |
| 35 | `CAP_WAKE_ALARM` | WAKE_ALARM | Trigger something that will wake up the system | `timerfd_create(CLOCK_REALTIME_ALARM\|CLOCK_BOOTTIME_ALARM)`, `timer_settime` on those clocks |
| 36 | `CAP_BLOCK_SUSPEND` | BLOCK_SUSPEND | Employ features that can block system suspend | `epoll EPOLLWAKEUP`, write to `/proc/sys/wake_lock` |
| 37 | `CAP_AUDIT_READ` | AUDIT_READ | Allow reading the audit log via a multicast netlink socket | `socket(AF_NETLINK, …, NETLINK_AUDIT)` for reading |
| 38 | `CAP_PERFMON` | PERFMON | Allow performance monitoring via `perf_event_open(2)` | `perf_event_open` (since Linux 5.8) |
| 39 | `CAP_BPF` | BPF | Allow BPF operations via `bpf(2)` | `bpf(BPF_*`, …) (since Linux 5.8) |
| 40 | `CAP_CHECKPOINT_RESTORE` | CHECKPOINT_RESTORE | Allow processes to be checkpointed via checkpoint/restore in user namespace(2) | `clone3(set_tid=…)`, readlink `/proc/<pid>/map_files`, write to `/proc/sys/kernel/ns_last_pid` (since Linux 5.9) |

## Notes on `CAP_SYS_ADMIN`

Per the Linux `capabilities(7)` man page:

> Don't choose `CAP_SYS_ADMIN` if you can possibly avoid it! A vast proportion of existing capability checks are associated with this capability. It can plausibly be called "the new root".

**Skill rule**: never auto-add `CAP_SYS_ADMIN`. Only include it when:

- An unambiguous `mount`/`umount`/`pivot_root`/`swapon`/`swapoff`/`sethostname`/`setdomainname`/`setns`/`quotactl`/`fanotify_init`/`clone(CLONE_NEW*)` signal is found, OR
- The user confirms an ambiguous signal (e.g. `mount` import with no call site) in Pass 2.

## Capability bitmask

`flags` field in the Profile is a `Long` (64-bit). For now, only bit 0 is used (`NO_NEW_PRIVS`). The capability set itself is stored as a `List<String>` (not a bitmask) — each entry is the full constant name like `"CAP_NET_RAW"`.

## Recommended (convenience) set

When the user requests `recommended` mode, add these three to the minimal set (in addition to whatever static analysis found):

| Capability | Why |
|---|---|
| `CAP_DAC_READ_SEARCH` | Lets the confined app `ls` / read protected paths — same privileges as a shell user, useful for debugging/forensics tools |
| `CAP_KILL` | Lets the app cleanly signal child processes (e.g. shell wrappers, server supervisors) |
| `CAP_SYS_RESOURCE` | Lets the app override RLIMIT_NOFILE etc. — useful for fork-heavy tools and avoid spurious OOM/EAGAIN |

These are documented as opt-in only; the skill does not add them in `minimal` mode.
