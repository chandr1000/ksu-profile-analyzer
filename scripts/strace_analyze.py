#!/usr/bin/env python3
"""
ksu-profile-analyzer — strace log parser.

Parses `strace -ff -o ...` output files and emits a findings.json with the
same shape as the static pipelines. Each signal is tagged `source: "strace:trace.<pid>"`
so the merged findings.json can show what came from runtime vs static.

Usage:
    python3 strace_analyze.py <log_dir> [--workdir <dir>] [--package-name <pkg>]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Strace line: optional "[pid N] " prefix, then syscall(args) = result
LINE_RE = re.compile(r'^\s*(?:\[pid\s+\d+\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)\s*=\s*(.+)$')

# Special argument parsers
# bind to port: bind(fd, {sa_family=..., sin_port=htons(N)}, ...)
BIND_RE = re.compile(r'\bbind\(\d+,\s*\{sa_family=AF_INET(?:6)?,\s*sin_port=htons\((\d+)\)\}')

# socket(family, type, protocol)
SOCKET_RE = re.compile(r'\bsocket\((AF_[A-Z0-9]+),\s*(SOCK_[A-Z0-9_]+)')

# clone / setns with CLONE_NEW*
CLONE_FLAGS_RE = re.compile(r'\b(?:clone|setns)\([^,]*,\s*([^)]*CLONE_NEW[A-Z]+[^)]*)')

# setsockopt SO_*
SETSOCKOPT_RE = re.compile(r'\bsetsockopt\(\d+,\s*SOL_SOCKET,\s*(SO_[A-Z_]+)')

# setxattr(path, "security.<X>", ...)
SETXATTR_RE = re.compile(r'\b(?:set|f|l)setxattr\([^,]+,\s*"(security\.[^"]+)"')

# openat / open path
OPENAT_RE = re.compile(r'\bopen(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)"')

# execve path
EXECVE_RE = re.compile(r'\bexecve\("([^"]+)"')

# Syscall → caps (subset of reference/syscall_to_cap.md — only the ones that
# can be unambiguously inferred from name only; argument parsing handled above)
SYSCALL_NAME_MAP: dict[str, dict] = {
    "mount": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "umount": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "umount2": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "pivot_root": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "swapon": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "swapoff": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "sethostname": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "setdomainname": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "quotactl": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "setns": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "fanotify_init": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "setuid": {"caps": ["CAP_SETUID"], "confidence": "unambiguous"},
    "seteuid": {"caps": ["CAP_SETUID"], "confidence": "unambiguous"},
    "setresuid": {"caps": ["CAP_SETUID"], "confidence": "unambiguous"},
    "setreuid": {"caps": ["CAP_SETUID"], "confidence": "unambiguous"},
    "setfsuid": {"caps": ["CAP_SETUID"], "confidence": "unambiguous"},
    "setgid": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "setegid": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "setresgid": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "setregid": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "setfsgid": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "setgroups": {"caps": ["CAP_SETGID"], "confidence": "unambiguous"},
    "chroot": {"caps": ["CAP_SYS_CHROOT"], "confidence": "unambiguous"},
    "ptrace": {"caps": ["CAP_SYS_PTRACE"], "confidence": "unambiguous"},
    "process_vm_readv": {"caps": ["CAP_SYS_PTRACE"], "confidence": "unambiguous"},
    "process_vm_writev": {"caps": ["CAP_SYS_PTRACE"], "confidence": "unambiguous"},
    "kcmp": {"caps": ["CAP_SYS_PTRACE"], "confidence": "unambiguous"},
    "mknod": {"caps": ["CAP_MKNOD"], "confidence": "unambiguous"},
    "mknodat": {"caps": ["CAP_MKNOD"], "confidence": "unambiguous"},
    "reboot": {"caps": ["CAP_SYS_BOOT"], "confidence": "unambiguous"},
    "kexec_load": {"caps": ["CAP_SYS_BOOT"], "confidence": "unambiguous"},
    "kexec_file_load": {"caps": ["CAP_SYS_BOOT"], "confidence": "unambiguous"},
    "init_module": {"caps": ["CAP_SYS_MODULE"], "confidence": "unambiguous"},
    "finit_module": {"caps": ["CAP_SYS_MODULE"], "confidence": "unambiguous"},
    "delete_module": {"caps": ["CAP_SYS_MODULE"], "confidence": "unambiguous"},
    "iopl": {"caps": ["CAP_SYS_RAWIO"], "confidence": "unambiguous"},
    "ioperm": {"caps": ["CAP_SYS_RAWIO"], "confidence": "unambiguous"},
    "settimeofday": {"caps": ["CAP_SYS_TIME"], "confidence": "unambiguous"},
    "stime": {"caps": ["CAP_SYS_TIME"], "confidence": "unambiguous"},
    "adjtimex": {"caps": ["CAP_SYS_TIME"], "confidence": "unambiguous"},
    "clock_settime": {"caps": ["CAP_SYS_TIME"], "confidence": "unambiguous"},
    "vhangup": {"caps": ["CAP_SYS_TTY_CONFIG"], "confidence": "unambiguous"},
    "acct": {"caps": ["CAP_SYS_PACCT"], "confidence": "unambiguous"},
    "bpf": {"caps": ["CAP_BPF"], "confidence": "unambiguous"},
    "perf_event_open": {"caps": ["CAP_PERFMON"], "confidence": "unambiguous"},
    "clone3": {"caps": ["CAP_CHECKPOINT_RESTORE"], "confidence": "ambiguous"},
    "setrlimit": {"caps": ["CAP_SYS_RESOURCE"], "confidence": "ambiguous"},
    "prlimit": {"caps": ["CAP_SYS_RESOURCE"], "confidence": "ambiguous"},
    "mlock": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "mlock2": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "mlockall": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "shmctl": {"caps": ["CAP_IPC_LOCK"], "confidence": "ambiguous"},
    "kill": {"caps": ["CAP_KILL"], "confidence": "ambiguous"},
    "tgkill": {"caps": ["CAP_KILL"], "confidence": "ambiguous"},
    "tkill": {"caps": ["CAP_KILL"], "confidence": "ambiguous"},
    "pidfd_send_signal": {"caps": ["CAP_KILL"], "confidence": "ambiguous"},
    "chown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous"},
    "fchown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous"},
    "lchown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous"},
    "fchownat": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous"},
    "setcap": {"caps": ["CAP_SETFCAP"], "confidence": "unambiguous"},
    "capset": {"caps": ["CAP_SETPCAP"], "confidence": "unambiguous"},
    "timerfd_create": {"caps": ["CAP_WAKE_ALARM"], "confidence": "ambiguous"},
    "nice": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous"},
    "setpriority": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous"},
    "sched_setscheduler": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous"},
    "sched_setattr": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous"},
    "open_by_handle_at": {"caps": ["CAP_DAC_READ_SEARCH"], "confidence": "unambiguous"},
    "setxattr": {"caps": ["CAP_SETFCAP"], "confidence": "ambiguous"},
    "fsetxattr": {"caps": ["CAP_SETFCAP"], "confidence": "ambiguous"},
    "lsetxattr": {"caps": ["CAP_SETFCAP"], "confidence": "ambiguous"},
    "epoll_ctl": {"caps": ["CAP_BLOCK_SUSPEND"], "confidence": "ambiguous"},
}

# Path → caps/groups (mirrors reference/syscall_to_cap.md "Device nodes" section)
# This PATH_MAP is consulted for BOTH:
#   - openat(path, ...) calls (the path is the first arg)
#   - write(fd<path>, ...) / read(fd<path>, ...) calls (the path is in the -y fd annotation)
# So adding an entry here covers BOTH the open and the write/read cases.
PATH_MAP = {
    "/dev/mem": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/dev/kmem": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/proc/kcore": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/dev/uhid": {"caps": [], "groups": [3011], "confidence": "unambiguous"},
    "/dev/dm-": {"caps": ["CAP_SYS_ADMIN"], "groups": [], "confidence": "unambiguous"},
    "/dev/block/": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "ambiguous"},
    "/dev/loop": {"caps": ["CAP_SYS_ADMIN"], "groups": [], "confidence": "unambiguous"},
    "/sys/kernel/debug/": {"caps": ["CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "ambiguous"},
    "/sys/kernel/tracing/": {"caps": ["CAP_SYS_ADMIN", "CAP_PERFMON"], "groups": [3012], "confidence": "ambiguous"},
    "/data/adb/ksu/": {"caps": ["CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/data/adb/modules/": {"caps": ["CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/xbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/bin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/sbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/sbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/proc/": {"caps": ["CAP_SYS_PTRACE"], "groups": [], "confidence": "ambiguous"},  # only if other pid
    # ---- NEW: configfs / sysfs / dev paths that are typically system:system mode 0660 ----
    # Writes to these paths return EACCES for root without CAP_DAC_OVERRIDE.
    # The classic case: USB gadget configfs — write(""<g1/UDC>"") to unbind the
    # default gadget, then write(<controller>) to bind a custom gadget.
    # Without CAP_DAC_OVERRIDE the unbind write fails silently, then the bind
    # fails downstream with EBUSY (because g1 still holds the controller).
    "/sys/kernel/config/usb_gadget/": {"caps": ["CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous"},
    "/sys/kernel/config/": {"caps": ["CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous"},
    "/sys/class/": {"caps": ["CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
    "/sys/devices/": {"caps": ["CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
    "/dev/hidg": {"caps": ["CAP_DAC_OVERRIDE", "CAP_FOWNER"], "groups": [], "confidence": "unambiguous"},  # USB HID gadget
    "/dev/usb/": {"caps": ["CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
    "/dev/input/": {"caps": ["CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
    "/dev/socket/": {"caps": ["CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
    "/proc/sys/": {"caps": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},  # /proc/sys/kernel/ etc.
    "/sys/module/": {"caps": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE"], "groups": [], "confidence": "ambiguous"},
}

# Syscalls that are normal noise — skip. These are the calls that NEVER imply
# a capability regardless of arguments. The file-descriptor I/O syscalls
# (read/write/pread/pwrite/readv/writev/sendfile/splice/copy_file_range/
# tee/vmsplice) were previously in this set, which was a bug — they CAN
# imply a capability when the fd points to a privileged path (e.g.
# write("/sys/kernel/config/usb_gadget/g1/UDC") needs CAP_DAC_OVERRIDE
# because the file is system:system mode 0660). They are now handled by
# the FD_PATH_HANDLER special handler in parse_line() instead.
NOISE_SYSCALLS = {
    "close", "fstat", "stat", "lstat", "newfstatat",
    "mmap", "munmap", "mprotect", "brk", "mremap", "msync", "mincore",
    "rt_sigprocmask", "rt_sigaction", "rt_sigreturn", "rt_sigtimedwait",
    "futex", "gettid", "getpid", "getuid", "geteuid", "getgid", "getegid",
    "getresuid", "getresgid", "getpgid", "getsid", "getppid",
    "clock_gettime", "gettimeofday", "time",
    "socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "getsockopt", "shutdown",  # unless option name requires cap (handled separately)
    "epoll_create", "epoll_create1", "epoll_wait", "epoll_pwait", "epoll_pwait2", "ppoll", "poll", "pselect6",
    "fcntl",  # unless F_SETLEASE (handled separately)
    "ioctl",  # unless special device
    "openat", "open",  # unless special path (handled separately)
    "readlinkat", "readlink", "getcwd", "chdir", "fchdir",
    "dup", "dup2", "dup3", "pipe", "pipe2", "eventfd", "eventfd2",
    "prctl",  # unless special (handled separately)
    "alarm", "setitimer", "timer_settime",
    "wait4", "waitpid", "exit", "exit_group",
    "uname", "getrandom", "rseq",
    "access", "faccesat", "faccessat2",
    "lseek",  # NOTE: pread/pwrite/readv/writev removed — handled by FD_PATH_HANDLER
    "fadvise64",
    "membarrier",
    "set_robust_list", "set_tid_address",
    "set_tid_address", "sched_yield", "sched_getaffinity", "sched_setaffinity",
    "sigaltstack",
}


def parse_line(line: str, log_file: str) -> list[dict]:
    """Parse a single strace line. Returns 0+ signals."""
    signals = []
    line = line.rstrip("\n")

    # Skip commentary lines (strace prints things like "--- SIGCHLD ---",
    # "+++ exited with 0 +++", "removed", or blank lines)
    stripped = line.lstrip()
    if not stripped or stripped.startswith("---") or stripped.startswith("+++") or stripped.startswith("removed"):
        return signals

    # Syscall name extraction — the line must start with optional [pid N] prefix
    # followed by a syscall name and an opening paren. This filter is authoritative;
    # anything else (signal descriptions, partial lines, etc.) is skipped here.
    m = re.match(r'^\s*(?:\[pid\s+\d+\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\(', line)
    if not m:
        return signals
    name = m.group(1)
    full_line = line

    # NOTE: The noise filter at the bottom of this function intentionally
    # runs AFTER the argument-based special handlers below. Syscalls like
    # `openat`, `socket`, `clone`, `setsockopt`, `setxattr`, `bind`, `write`,
    # `read`, `pwrite`, `pread`, `writev`, `readv` are all "noisy" in the
    # sense that most invocations don't imply a capability — but specific
    # argument patterns (openat("/dev/mem"), socket(AF_PACKET, SOCK_RAW),
    # clone(CLONE_NEWNS), setsockopt(SO_MARK), setxattr("security.
    # capability"), bind(port<1024), write("/sys/kernel/config/...UDC"))
    # DO imply capabilities. Running the noise filter early would skip
    # those checks.

    # Argument-based special handling
    # 0. File-descriptor I/O syscalls (write/read/pwrite/pread/writev/readv)
    #    These rely on the strace `-y` flag's fd→path annotation. Without
    #    `-y`, strace prints `write(3, "", 0)` — the fd number alone is
    #    useless for capability mapping. With `-y`, strace prints
    #    `write(3</sys/kernel/config/usb_gadget/g1/UDC>, "", 0)` and we
    #    can extract the path and consult PATH_MAP.
    #    This handler is critical: it catches the write-to-configfs pattern
    #    that needs CAP_DAC_OVERRIDE (Android's USB gadget paths are
    #    system:system mode 0660, root w/o DAC_OVERRIDE can't bypass).
    if name in ("write", "read", "pwrite", "pread", "writev", "readv",
                "sendfile", "splice", "copy_file_range", "tee", "vmsplice"):
        # Extract the -y fd→path annotation: `write(3</some/path>, ...)`
        # The annotation is `<` followed by the path, followed by `>`.
        fd_path_match = re.search(r'\b\d+<([^>]+)>', line)
        if fd_path_match:
            p = fd_path_match.group(1)
            # Look up the most specific matching key in PATH_MAP
            matched = None
            for k, v in PATH_MAP.items():
                if p.startswith(k) or p == k.rstrip("/"):
                    if matched is None or len(k) > len(matched[0]):
                        matched = (k, v)
            if matched is not None:
                k, v = matched
                signals.append({
                    "kind": "file_path",
                    "name": p,
                    "source": f"strace:{log_file}",
                    "evidence": full_line[:300],
                    "confidence": v["confidence"],
                    "implied_caps": v["caps"],
                    "implied_groups": v["groups"],
                    "sets_allow_su": v.get("sets_allow_su", False),
                    "via_syscall": name,  # tells the user how this path was discovered
                    "note": f"{name}() to privileged path {k!r} (fd annotation)",
                })
                return signals
        # If no -y annotation OR no PATH_MAP match — no capability signal.
        # The call was either a normal file I/O (no special path) OR strace
        # was run without -y. Both cases produce no signal.
        return signals

    # 1. bind to port
    m_bind = BIND_RE.search(line)
    if m_bind:
        port = int(m_bind.group(1))
        if port < 1024:
            signals.append({
                "kind": "syscall",
                "name": f"bind(port={port})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "implied_cap": "CAP_NET_BIND_SERVICE",
            })
            return signals
        return signals  # bind to high port — no cap

    # 2. socket(family, type, ...)
    m_sock = SOCKET_RE.search(line)
    if m_sock:
        family, stype = m_sock.group(1), m_sock.group(2)
        if family in ("AF_PACKET",) and "SOCK_RAW" in stype:
            signals.append({
                "kind": "syscall",
                "name": f"socket({family}, {stype})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "implied_cap": "CAP_NET_RAW",
                "implied_group": 3004,
            })
            return signals
        if family in ("AF_INET", "AF_INET6") and "SOCK_RAW" in stype:
            signals.append({
                "kind": "syscall",
                "name": f"socket({family}, {stype})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "implied_cap": "CAP_NET_RAW",
                "implied_group": 3004,
            })
            return signals
        return signals  # regular socket — no cap

    # 3. clone / clone3 / setns with CLONE_NEW* (excluding CLONE_NEWUSER,
    #    which doesn't require a capability on modern kernels).
    # Note: for `clone`, the flags are the FIRST argument (the regex above
    # used to look in the second argument, which was wrong — for `clone3`
    # the flags are inside a struct as `flags=CLONE_NEW*|...`). The simplest
    # reliable signal is just: name is clone/clone3/setns AND the line
    # contains CLONE_NEW (and not only CLONE_NEWUSER).
    if name in ("clone", "clone3", "setns") and "CLONE_NEW" in line:
        # Extract the flag set for the signal name (best-effort)
        flag_match = re.search(r'(CLONE_NEW[A-Z_]+(?:\|CLONE_NEW[A-Z_]+)*)', line)
        flag_str = flag_match.group(1) if flag_match else "CLONE_NEW*"
        # If the only NEW* flag is CLONE_NEWUSER, no capability needed
        if flag_str == "CLONE_NEWUSER":
            return signals
        signals.append({
            "kind": "syscall",
            "name": f"{name}({flag_str})",
            "source": f"strace:{log_file}",
            "evidence": full_line[:300],
            "confidence": "unambiguous",
            "implied_cap": "CAP_SYS_ADMIN",
        })
        return signals

    # 4. setsockopt SO_*
    m_set = SETSOCKOPT_RE.search(line)
    if m_set:
        opt = m_set.group(1)
        if opt in ("SO_DEBUG", "SO_MARK", "SO_PRIORITY", "SO_RCVBUFFORCE", "SO_SNDBUFFORCE"):
            signals.append({
                "kind": "syscall",
                "name": f"setsockopt({opt})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "implied_cap": "CAP_NET_ADMIN",
                "implied_group": 3005,
            })
            return signals

    # 5. setxattr security.*
    m_setx = SETXATTR_RE.search(line)
    if m_setx:
        attr = m_setx.group(1)
        if attr == "security.capability":
            signals.append({
                "kind": "syscall",
                "name": f"setxattr({attr})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "implied_cap": "CAP_SETFCAP",
            })
        else:
            signals.append({
                "kind": "syscall",
                "name": f"setxattr({attr})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "ambiguous",
                "implied_cap": "CAP_SYS_ADMIN",
            })
        return signals

    # 6. openat / open with special path
    m_open = OPENAT_RE.search(line)
    if m_open:
        p = m_open.group(1)
        matched = None
        for k, v in PATH_MAP.items():
            if p.startswith(k) or p == k.rstrip("/"):
                if matched is None or len(k) > len(matched[0]):
                    matched = (k, v)
        if matched:
            k, v = matched
            signals.append({
                "kind": "file_path",
                "name": p,
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": v["confidence"],
                "implied_caps": v["caps"],
                "implied_groups": v["groups"],
                "sets_allow_su": v.get("sets_allow_su", False),
            })
        # else: open of normal file — no cap
        return signals

    # 7. execve /system/.../su
    m_exec = EXECVE_RE.search(line)
    if m_exec:
        p = m_exec.group(1)
        if p.endswith("/su") or p == "su":
            signals.append({
                "kind": "su_invocation",
                "name": f"execve({p})",
                "source": f"strace:{log_file}",
                "evidence": full_line[:300],
                "confidence": "unambiguous",
                "sets_allow_su": True,
            })
            return signals
        # other execve — no cap

    # 8. epoll_ctl with EPOLLWAKEUP
    if name == "epoll_ctl" and "EPOLLWAKEUP" in line:
        signals.append({
            "kind": "syscall",
            "name": "epoll_ctl(EPOLLWAKEUP)",
            "source": f"strace:{log_file}",
            "evidence": full_line[:300],
            "confidence": "unambiguous",
            "implied_cap": "CAP_BLOCK_SUSPEND",
        })
        return signals

    # 9. Noise filter — only reached if no special handler above matched.
    # These syscalls are normal app operation (read/write/mmap/etc.) and
    # have no capability implications. We also include `socket`/`openat`/
    # `setsockopt`/etc. here because their special-case handlers above
    # already returned for the cases that DO imply capabilities; if we
    # reach this point with one of these names, the call used benign
    # arguments (e.g. `openat("/data/data/foo/...", ...)`, `socket(AF_UNIX,
    # SOCK_STREAM, ...)`) and can be safely skipped.
    if name in NOISE_SYSCALLS:
        return signals

    # 10. Plain name lookup — for non-noise syscalls like mount, ptrace,
    # setuid, bpf, etc. that don't need argument inspection.
    info = SYSCALL_NAME_MAP.get(name)
    if info:
        signals.append({
            "kind": "syscall",
            "name": name,
            "source": f"strace:{log_file}",
            "evidence": full_line[:300],
            "confidence": info["confidence"],
            "implied_caps": info["caps"],
        })

    return signals


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log_dir", type=Path)
    ap.add_argument("--workdir", type=Path, default=None)
    ap.add_argument("--package-name", default=None)
    args = ap.parse_args()

    log_dir = args.log_dir.resolve()
    if not log_dir.is_dir():
        print(f"ERROR: log dir not found: {log_dir}", file=sys.stderr)
        return 2

    workdir = args.workdir or (Path("/home/z/my-project/scripts/_work") / log_dir.name)
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"[strace_analyze] log_dir={log_dir}", file=sys.stderr)
    print(f"[strace_analyze] workdir={workdir}", file=sys.stderr)

    log_files = sorted(log_dir.glob("trace.*"))
    if not log_files:
        # Try strace.<pid> naming (default when no -o prefix)
        log_files = sorted(log_dir.glob("strace.*"))
    if not log_files:
        print(f"ERROR: no trace.* files found in {log_dir}", file=sys.stderr)
        return 2

    print(f"[strace_analyze] found {len(log_files)} trace files", file=sys.stderr)

    signals: list[dict] = []
    per_pid_count: dict[str, int] = {}

    for log_file in log_files:
        pid_tag = log_file.name  # e.g. "trace.1234"
        try:
            text = log_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"  WARN: failed to read {log_file}: {e}", file=sys.stderr)
            continue
        count = 0
        for line in text.splitlines():
            line_signals = parse_line(line, pid_tag)
            signals.extend(line_signals)
            count += len(line_signals)
        per_pid_count[pid_tag] = count
        print(f"  {pid_tag}: {count} signals", file=sys.stderr)

    # Aggregate (count duplicates)
    agg: dict[tuple, dict] = {}
    for s in signals:
        key = (s["kind"], s["name"])
        if key not in agg:
            agg[key] = {**s, "count": 1}
        else:
            agg[key]["count"] += 1
    aggregated = list(agg.values())

    findings = {
        "target": str(log_dir),
        "target_type": "strace",
        "package_name": args.package_name,
        "pids_traced": [lf.name for lf in log_files],
        "per_pid_signal_count": per_pid_count,
        "signals": aggregated,
    }
    out_path = workdir / "findings.json"
    out_path.write_text(json.dumps(findings, indent=2))
    print(f"[strace_analyze] wrote {out_path} ({len(aggregated)} unique signals)", file=sys.stderr)
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
