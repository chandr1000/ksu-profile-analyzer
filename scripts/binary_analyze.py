#!/usr/bin/env python3
"""
ksu-profile-analyzer — ELF binary analysis pipeline.

Usage:
    python3 binary_analyze.py <elf_path> [--parent-source <tag>] [--workdir <dir>]

Outputs a findings.json file in the workdir (default: /home/z/my-project/scripts/_work/<elf_basename>/findings.json).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Imported libc symbol → caps (mirrors reference/syscall_to_cap.md "Imported libc symbols" section)
SYMBOL_MAP: dict[str, dict] = {
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
    "setxattr": {"caps": ["CAP_SETFCAP"], "confidence": "ambiguous", "note": "depends on attribute name"},
    "lsetxattr": {"caps": ["CAP_SETFCP"], "confidence": "ambiguous", "note": "depends on attribute name"},
    "fsetxattr": {"caps": ["CAP_SETFCP"], "confidence": "ambiguous", "note": "depends on attribute name"},
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
    "clone3": {"caps": ["CAP_CHECKPOINT_RESTORE"], "confidence": "ambiguous", "note": "only if set_tid used"},
    "setrlimit": {"caps": ["CAP_SYS_RESOURCE"], "confidence": "ambiguous", "note": "raising limits needs cap"},
    "prlimit": {"caps": ["CAP_SYS_RESOURCE"], "confidence": "ambiguous", "note": "raising limits needs cap"},
    "mlock": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "mlockall": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "mlock2": {"caps": ["CAP_IPC_LOCK"], "confidence": "unambiguous"},
    "shmctl": {"caps": ["CAP_IPC_LOCK"], "confidence": "ambiguous", "note": "only with SHM_LOCK"},
    "kill": {"caps": ["CAP_KILL"], "confidence": "ambiguous", "note": "only if target is different uid"},
    "tgkill": {"caps": ["CAP_KILL"], "confidence": "ambiguous", "note": "only if target is different uid"},
    "tkill": {"caps": ["CAP_KILL"], "confidence": "ambiguous", "note": "only if target is different uid"},
    "pidfd_send_signal": {"caps": ["CAP_KILL"], "confidence": "ambiguous", "note": "only if target is different uid"},
    "chown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous", "note": "only if arbitrary"},
    "fchown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous", "note": "only if arbitrary"},
    "lchown": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous", "note": "only if arbitrary"},
    "fchownat": {"caps": ["CAP_CHOWN"], "confidence": "ambiguous", "note": "only if arbitrary"},
    "chmod": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "fchmod": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "fchmodat": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "utime": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "utimes": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "utimensat": {"caps": ["CAP_FOWNER"], "confidence": "ambiguous", "note": "only on others' files"},
    "setcap": {"caps": ["CAP_SETFCAP"], "confidence": "unambiguous"},
    "capset": {"caps": ["CAP_SETPCAP"], "confidence": "unambiguous"},
    "timerfd_create": {"caps": ["CAP_WAKE_ALARM"], "confidence": "ambiguous", "note": "only with CLOCK_REALTIME_ALARM/BOOTTIME_ALARM"},
    "nice": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous", "note": "only if targeting other procs"},
    "setpriority": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous", "note": "only if targeting other procs"},
    "sched_setscheduler": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous", "note": "only if targeting other procs"},
    "sched_setattr": {"caps": ["CAP_SYS_NICE"], "confidence": "ambiguous", "note": "only if targeting other procs"},
    "open_by_handle_at": {"caps": ["CAP_DAC_READ_SEARCH"], "confidence": "unambiguous"},
    "linkat": {"caps": ["CAP_DAC_READ_SEARCH"], "confidence": "ambiguous", "note": "only with AT_EMPTY_PATH"},
}

# Path → caps/groups (mirrors "Device nodes" section)
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
}

# Interesting DT_NEEDED libraries (mirrors "Needed libraries" note in syscall_to_cap.md)
NEEDED_LIB_MAP = {
    "libcap.so": {"caps": ["CAP_SETFCAP"], "confidence": "unambiguous"},
    "libselinux.so": {"caps": [], "groups": [], "confidence": "unambiguous", "note": "SELinux ops"},
    "libaudit.so": {"caps": ["CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL"], "confidence": "unambiguous"},
    "libbpf.so": {"caps": ["CAP_BPF"], "confidence": "unambiguous"},
    "libperfmon.so": {"caps": ["CAP_PERFMON"], "confidence": "unambiguous"},
    "libmount.so": {"caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "libblkid.so": {"caps": ["CAP_SYS_ADMIN"], "confidence": "ambiguous", "note": "block dev enumeration"},
}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def get_arch(elf: Path) -> str | None:
    out = run(["file", str(elf)])
    if "aarch64" in out.stdout or "ARM aarch64" in out.stdout:
        return "arm64-v8a"
    if "ARM" in out.stdout:
        return "armeabi-v7a"
    if "x86-64" in out.stdout or "x86_64" in out.stdout:
        return "x86_64"
    if "Intel 80386" in out.stdout or "i386" in out.stdout:
        return "x86"
    if "RISC-V" in out.stdout:
        return "riscv64"
    return None


def get_dynamic_imports(elf: Path) -> list[str]:
    """Return list of imported (undefined) dynamic symbol names.

    `nm -D --undefined-only` output format on most platforms is:
        `                 U symbol@VERSION`
    where the first column is blank/`U`/`w`/`v` (the symbol type), and the
    symbol name is the LAST whitespace-separated token. We split() and take
    the last token, then strip the `@VERSION` suffix.

    `readelf -W --dyn-syms` output is more verbose:
        `   N: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mount@GLIBC_2.2.5 (3)`
    We look for lines containing `UND` and extract the last token before `(N)`.
    """
    out = run(["nm", "-D", "--undefined-only", str(elf)])
    if out.returncode == 0 and out.stdout.strip():
        symbols = []
        for line in out.stdout.splitlines():
            line = line.rstrip()
            if not line.strip():
                continue
            # Last whitespace-separated token is the symbol name
            tokens = line.split()
            if not tokens:
                continue
            sym = tokens[-1]
            # Strip @VERSION suffix
            sym = sym.split("@")[0]
            # Skip nm type letters that may end up as the last token if the
            # line had only a type marker (rare).
            if sym in {"U", "u", "w", "v", "W", "V"} or len(sym) < 2:
                continue
            symbols.append(sym)
        return symbols
    # Fallback to readelf
    out = run(["readelf", "-W", "--dyn-syms", str(elf)])
    symbols = []
    for line in out.stdout.splitlines():
        if "UND" not in line:
            continue
        # Format: "   N: ... UND <symbol>@VERSION (V)"
        # Extract the last token before the optional "(N)" version annotation
        # Strip trailing " (N)" first
        line_clean = re.sub(r'\s*\(\d+\)\s*$', '', line)
        tokens = line_clean.split()
        if not tokens:
            continue
        sym = tokens[-1]
        sym = sym.split("@")[0]
        if sym == "UND" or len(sym) < 2:
            continue
        symbols.append(sym)
    return symbols


def get_needed_libs(elf: Path) -> list[str]:
    """Parse NEEDED entries from the dynamic section.

    `readelf -d` output format varies slightly:
        ` 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]`
    Some readelf versions omit the parens. We accept both forms.
    """
    out = run(["readelf", "-d", str(elf)])
    libs = []
    for line in out.stdout.splitlines():
        # Match: `(NEEDED)  Shared library: [name]`  OR  `NEEDED  Shared library: [name]`
        m = re.search(r'\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]', line)
        if not m:
            m = re.search(r'\bNEEDED\s+Shared library:\s+\[([^\]]+)\]', line)
        if m:
            libs.append(m.group(1))
    return libs


def get_jni_entry_points(elf: Path) -> list[str]:
    out = run(["readelf", "-W", "--dyn-syms", str(elf)])
    jni = []
    for line in out.stdout.splitlines():
        m = re.search(r'\b(Java_[A-Za-z0-9_]+)\b', line)
        if m:
            jni.append(m.group(1))
    return jni


def get_strings(elf: Path, min_len: int = 4) -> str:
    out = run(["strings", "-a", "-n", str(min_len), str(elf)])
    return out.stdout


def is_stripped(elf: Path) -> bool:
    out = run(["nm", str(elf)], check=False)
    return "no symbols" in (out.stderr + out.stdout).lower()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf_path", type=Path)
    ap.add_argument("--parent-source", default=None,
                    help="Tag for source attribution (e.g. apk:lib/arm64-v8a/libfoo.so)")
    ap.add_argument("--workdir", type=Path, default=None,
                    help="Working directory (default: /home/z/my-project/scripts/_work/<elf_basename>)")
    args = ap.parse_args()

    elf = args.elf_path.resolve()
    if not elf.is_file():
        print(f"ERROR: ELF not found: {elf}", file=sys.stderr)
        return 2

    workdir = args.workdir or (Path("/home/z/my-project/scripts/_work") / elf.name)
    workdir.mkdir(parents=True, exist_ok=True)

    source_tag = args.parent_source or f"binary:{elf.name}"

    print(f"[binary_analyze] target={elf}", file=sys.stderr)
    print(f"[binary_analyze] workdir={workdir}", file=sys.stderr)
    print(f"[binary_analyze] source_tag={source_tag}", file=sys.stderr)

    signals: list[dict] = []

    # 1. Arch
    arch = get_arch(elf)
    print(f"[binary_analyze] arch={arch}", file=sys.stderr)

    # 2. Stripped / packed?
    stripped = is_stripped(elf)
    print(f"[binary_analyze] stripped={stripped}", file=sys.stderr)
    if stripped:
        signals.append({
            "kind": "stripped_binary",
            "name": elf.name,
            "source": source_tag,
            "evidence": "nm reports 'no symbols'",
            "confidence": "unambiguous",
        })

    # 3. Dynamic imports
    print("[binary_analyze] extracting dynamic imports...", file=sys.stderr)
    imports = get_dynamic_imports(elf)
    for sym in imports:
        info = SYMBOL_MAP.get(sym)
        if not info:
            continue
        signals.append({
            "kind": "syscall",
            "name": sym,
            "source": source_tag,
            "evidence": "imported dynamic symbol (UND in .dynsym)",
            "confidence": info["confidence"],
            "note": info.get("note"),
        })

    # 4. NEEDED libs
    print("[binary_analyze] extracting NEEDED libs...", file=sys.stderr)
    needed = get_needed_libs(elf)
    for lib in needed:
        info = NEEDED_LIB_MAP.get(lib)
        if not info:
            continue
        signals.append({
            "kind": "needed_lib",
            "name": lib,
            "source": source_tag,
            "evidence": "DT_NEEDED entry",
            "confidence": info["confidence"],
            "note": info.get("note"),
        })
        for cap in info.get("caps", []):
            signals.append({
                "kind": "syscall",
                "name": f"<lib:{lib}>",
                "source": source_tag,
                "evidence": f"NEEDED {lib} (implies {cap})",
                "confidence": info["confidence"],
            })

    # 5. JNI entry points
    print("[binary_analyze] extracting JNI entry points...", file=sys.stderr)
    jni = get_jni_entry_points(elf)

    # 6. Strings — file paths / su paths
    print("[binary_analyze] scanning strings for paths...", file=sys.stderr)
    strings_out = get_strings(elf)
    seen_paths = set()
    for prefix in ("/dev/", "/proc/", "/sys/", "/data/adb/", "/system/xbin/", "/system/bin/", "/system/sbin/", "/sbin/"):
        for m in re.finditer(re.escape(prefix) + r"[A-Za-z0-9_./-]+", strings_out):
            p = m.group(0).strip().strip('"').strip("'").rstrip("/")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            # Look up the most specific match in PATH_MAP (longest-prefix match)
            matched = None
            for k, v in PATH_MAP.items():
                if p.startswith(k) or p == k.rstrip("/"):
                    if matched is None or len(k) > len(matched[0]):
                        matched = (k, v)
            if matched is None:
                # Generic file_path signal — no cap/group mapping
                signals.append({
                    "kind": "file_path",
                    "name": p,
                    "source": source_tag,
                    "evidence": "string table",
                    "confidence": "ambiguous",
                })
                continue
            k, v = matched
            signals.append({
                "kind": "file_path",
                "name": p,
                "source": source_tag,
                "evidence": "string table",
                "confidence": v["confidence"],
                "note": f"matched PATH_MAP key {k!r}",
                "sets_allow_su": v.get("sets_allow_su", False),
            })

    # 7. Emit findings.json
    findings = {
        "target": str(elf),
        "target_type": "elf",
        "arch": arch,
        "is_stripped": stripped,
        "is_packed": False,  # Not detected reliably; strace pipeline handles this
        "needed_libs": needed,
        "jni_entry_points": jni,
        "signals": signals,
    }
    out_path = workdir / "findings.json"
    out_path.write_text(json.dumps(findings, indent=2))
    print(f"[binary_analyze] wrote {out_path} ({len(signals)} signals)", file=sys.stderr)
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
