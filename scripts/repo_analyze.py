#!/usr/bin/env python3
"""
ksu-profile-analyzer — Source repo analysis pipeline.

Usage:
    python3 repo_analyze.py <repo_path> [--workdir <dir>]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# C/C++ syscall regexes (mirrors pipelines/repo.md "C / C++" section)
C_PATTERNS: list[tuple[str, str, str]] = [
    (r'\bsetuid\s*\(', "setuid", "unambiguous"),
    (r'\bsetgid\s*\(', "setgid", "unambiguous"),
    (r'\bsetresuid\s*\(', "setresuid", "unambiguous"),
    (r'\bsetresgid\s*\(', "setresgid", "unambiguous"),
    (r'\bsetfsuid\s*\(', "setfsuid", "unambiguous"),
    (r'\bsetfsgid\s*\(', "setfsgid", "unambiguous"),
    (r'\bsetgroups\s*\(', "setgroups", "unambiguous"),
    (r'\bptrace\s*\(', "ptrace", "unambiguous"),
    (r'\bprocess_vm_readv\s*\(', "process_vm_readv", "unambiguous"),
    (r'\bprocess_vm_writev\s*\(', "process_vm_writev", "unambiguous"),
    (r'\bkcmp\s*\(', "kcmp", "unambiguous"),
    (r'\bmount\s*\(', "mount", "unambiguous"),
    (r'\bumount2?\s*\(', "umount", "unambiguous"),
    (r'\bpivot_root\s*\(', "pivot_root", "unambiguous"),
    (r'\bswapon\s*\(', "swapon", "unambiguous"),
    (r'\bswapoff\s*\(', "swapoff", "unambiguous"),
    (r'\bsethostname\s*\(', "sethostname", "unambiguous"),
    (r'\bsetdomainname\s*\(', "setdomainname", "unambiguous"),
    (r'\bquotactl\s*\(', "quotactl", "unambiguous"),
    (r'\bsetns\s*\(', "setns", "unambiguous"),
    (r'\bfanotify_init\s*\(', "fanotify_init", "unambiguous"),
    (r'\bchroot\s*\(', "chroot", "unambiguous"),
    (r'\bmknod\s*\(', "mknod", "unambiguous"),
    (r'\bmknodat\s*\(', "mknodat", "unambiguous"),
    (r'\breboot\s*\(', "reboot", "unambiguous"),
    (r'\bkexec_load\s*\(', "kexec_load", "unambiguous"),
    (r'\bkexec_file_load\s*\(', "kexec_file_load", "unambiguous"),
    (r'\binit_module\s*\(', "init_module", "unambiguous"),
    (r'\bfinit_module\s*\(', "finit_module", "unambiguous"),
    (r'\bdelete_module\s*\(', "delete_module", "unambiguous"),
    (r'\biopl\s*\(', "iopl", "unambiguous"),
    (r'\bioperm\s*\(', "ioperm", "unambiguous"),
    (r'\bsettimeofday\s*\(', "settimeofday", "unambiguous"),
    (r'\badjtimex\s*\(', "adjtimex", "unambiguous"),
    (r'\bclock_settime\s*\(', "clock_settime", "unambiguous"),
    (r'\bvhangup\s*\(', "vhangup", "unambiguous"),
    (r'\bacct\s*\(', "acct", "unambiguous"),
    (r'\bbpf\s*\(', "bpf", "unambiguous"),
    (r'\bperf_event_open\s*\(', "perf_event_open", "unambiguous"),
    (r'\bclone3\s*\(', "clone3", "ambiguous"),
    (r'\bsetrlimit\s*\(', "setrlimit", "ambiguous"),
    (r'\bprlimit\s*\(', "prlimit", "ambiguous"),
    (r'\bmlock\s*\(', "mlock", "unambiguous"),
    (r'\bmlockall\s*\(', "mlockall", "unambiguous"),
    (r'\bshmctl\s*\(', "shmctl", "ambiguous"),
    (r'\bkill\s*\(', "kill", "ambiguous"),
    (r'\btgkill\s*\(', "tgkill", "ambiguous"),
    (r'\bpidfd_send_signal\s*\(', "pidfd_send_signal", "ambiguous"),
    (r'\bchown\s*\(', "chown", "ambiguous"),
    (r'\bfchown\s*\(', "fchown", "ambiguous"),
    (r'\blchown\s*\(', "lchown", "ambiguous"),
    (r'\bfchownat\s*\(', "fchownat", "ambiguous"),
    (r'\bsetxattr\s*\(', "setxattr", "ambiguous"),
    (r'\bfsetxattr\s*\(', "fsetxattr", "ambiguous"),
    (r'\bsetcap\s*\(', "setcap", "unambiguous"),
    (r'\bcapset\s*\(', "capset", "unambiguous"),
    (r'\btimerfd_create\s*\(', "timerfd_create", "ambiguous"),
    (r'\bnice\s*\(', "nice", "ambiguous"),
    (r'\bsetpriority\s*\(', "setpriority", "ambiguous"),
    (r'\bsched_setscheduler\s*\(', "sched_setscheduler", "ambiguous"),
    (r'\bsched_setattr\s*\(', "sched_setattr", "ambiguous"),
    (r'\bopen_by_handle_at\s*\(', "open_by_handle_at", "unambiguous"),
    (r'\blinkat\s*\(', "linkat", "ambiguous"),
]

GO_PATTERNS = [
    (r'syscall\.Setuid\b', "syscall.Setuid", "unambiguous"),
    (r'syscall\.Setgid\b', "syscall.Setgid", "unambiguous"),
    (r'syscall\.Setgroups\b', "syscall.Setgroups", "unambiguous"),
    (r'syscall\.Mount\b', "syscall.Mount", "unambiguous"),
    (r'syscall\.Unmount\b', "syscall.Unmount", "unambiguous"),
    (r'syscall\.PivotRoot\b', "syscall.PivotRoot", "unambiguous"),
    (r'syscall\.Swapon\b', "syscall.Swapon", "unambiguous"),
    (r'syscall\.Swapoff\b', "syscall.Swapoff", "unambiguous"),
    (r'syscall\.Sethostname\b', "syscall.Sethostname", "unambiguous"),
    (r'syscall\.Ptrace\b', "syscall.Ptrace", "unambiguous"),
    (r'syscall\.Reboot\b', "syscall.Reboot", "unambiguous"),
    (r'syscall\.Mknod\b', "syscall.Mknod", "unambiguous"),
    (r'\bunix\.', "golang.org/x/sys/unix call", "ambiguous"),
]

RUST_PATTERNS = [
    (r'nix::unistd::setuid\b', "nix::unistd::setuid", "unambiguous"),
    (r'nix::unistd::setgid\b', "nix::unistd::setgid", "unambiguous"),
    (r'nix::unistd::setgroups\b', "nix::unistd::setgroups", "unambiguous"),
    (r'nix::mount::mount\b', "nix::mount::mount", "unambiguous"),
    (r'nix::mount::umount\b', "nix::mount::umount", "unambiguous"),
    (r'nix::sched::setns\b', "nix::sched::setns", "unambiguous"),
    (r'nix::unistd::chroot\b', "nix::unistd::chroot", "unambiguous"),
    (r'nix::unistd::ptrace\b', "nix::unistd::ptrace", "unambiguous"),
    (r'libc::setuid\b', "libc::setuid", "unambiguous"),
    (r'libc::mount\b', "libc::mount", "unambiguous"),
    (r'libc::ptrace\b', "libc::ptrace", "unambiguous"),
    (r'libc::reboot\b', "libc::reboot", "unambiguous"),
    (r'libc::mknod\b', "libc::mknod", "unambiguous"),
]

JAVA_PATTERNS = [
    (r'Runtime\.getRuntime\(\)\.exec\(\s*"su"', "Runtime.exec(\"su\")", "unambiguous"),
    (r'ProcessBuilder\(\s*(?:new\s+String\[\]\s*\{)?\s*"su"', "ProcessBuilder(\"su\")", "unambiguous"),
    (r'Lcom/topjohnwu/superuser/Shell;->su\b', "Shell.su (libsu)", "unambiguous"),
    (r'Lcom/topjohnwu/superuser/Shell;->cmd\b', "Shell.cmd (libsu)", "unambiguous"),
    (r'com\.topjohnwu\.superuser', "libsu import", "unambiguous"),
    (r'com\.topjohnwu\.magisk', "MagiskBean import", "unambiguous"),
    (r'loadLibrary\(\s*"([^"]+)"', "loadLibrary(<name>)", "unambiguous"),
    (r'new ServerSocket\(\s*(\d{1,3})\s*\)', "new ServerSocket(port)", "unambiguous"),
    (r'new DatagramSocket\(\s*(\d{1,3})\s*\)', "new DatagramSocket(port)", "unambiguous"),
]

JNI_DECL_PATTERN = re.compile(r'JNIEXPORT\s+\S+\s+\*?\s*(Java_[A-Za-z0-9_]+)\s*\(')
JAVA_NATIVE_PATTERN = re.compile(r'\bnative\s+\S+\s+\w+\s*\(')

# Path patterns
PATH_PATTERNS = [
    r'"/dev/[^"]+"',
    r'"/proc/[^"]+"',
    r'"/sys/[^"]+"',
    r'"/data/adb/[^"]+"',
    r'"/system/(?:xbin|bin|sbin)/su"',
    r'"/sbin/su"',
]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def find_files(repo: Path, extensions: list[str]) -> list[Path]:
    """Find source files by extension, excluding build/test/vendor dirs."""
    skip_dirs = {".git", "build", ".gradle", "node_modules", ".idea", ".vs",
                 "vendor", "third_party", "tests", "test"}
    matches = []
    for root, dirs, files in os.walk(repo):
        # Prune skip dirs in-place
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for f in files:
            for ext in extensions:
                if f.endswith(ext):
                    matches.append(Path(root) / f)
                    break
    return matches


def scan_file(path: Path, patterns: list[tuple[str, str, str]], source_prefix: str) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    signals = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        # Skip commented lines (very crude)
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue
        for pat, name, conf in patterns:
            for m in re.finditer(pat, line):
                # Detect if inside #ifdef (rough heuristic)
                in_ifdef = False
                # Look backward for nearest #if/#else — very crude
                backward_text = text[:text.index(line)]
                last_if = backward_text.rfind("#if")
                last_else = backward_text.rfind("#else")
                if last_if != -1 and last_else != -1 and last_else > last_if:
                    in_ifdef = True
                signals.append({
                    "kind": "syscall",
                    "name": name,
                    "source": f"{source_prefix}:{path.relative_to(path.anchor if path.is_absolute() else '.')}:{line_no}",
                    "evidence": line.strip()[:200],
                    "confidence": "ambiguous" if in_ifdef else conf,
                })
    return signals


def scan_paths(repo: Path) -> list[dict]:
    """Scan all source files for hardcoded paths."""
    signals = []
    seen = set()
    files = find_files(repo, [".c", ".cpp", ".cc", ".h", ".hpp", ".java", ".kt", ".go", ".rs", ".py"])
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat in PATH_PATTERNS:
            for m in re.finditer(pat, text):
                p = m.group(0).strip('"').strip("'").rstrip("/")
                if p in seen:
                    continue
                seen.add(p)
                line_no = text[:m.start()].count("\n") + 1
                signals.append({
                    "kind": "file_path",
                    "name": p,
                    "source": f"repo:{f.relative_to(repo)}:{line_no}",
                    "evidence": f"string: {p}",
                    "confidence": "ambiguous",
                })
    return signals


def find_manifest(repo: Path) -> Path | None:
    for p in repo.rglob("AndroidManifest.xml"):
        # Skip build outputs
        if "build" in p.parts or ".gradle" in p.parts:
            continue
        return p
    return None


def parse_manifest(manifest: Path) -> tuple[str | None, list[str], str | None, str | None, str | None]:
    text = manifest.read_text(encoding="utf-8", errors="ignore")
    pkg_m = re.search(r'package="([^"]+)"', text)
    pkg = pkg_m.group(1) if pkg_m else None
    perms = sorted(set(re.findall(r'android:name="([^"]*android\.permission\.[^"]*)"', text)))
    vn_m = re.search(r'versionName="([^"]*)"', text)
    vn = vn_m.group(1) if vn_m else None
    vc_m = re.search(r'versionCode="(\d+)"', text)
    vc = vc_m.group(1) if vc_m else None
    su_m = re.search(r'sharedUserId="([^"]+)"', text)
    su = su_m.group(1) if su_m else None
    return pkg, perms, vn, vc, su


def identify_project_type(repo: Path) -> str | None:
    if (repo / "build.gradle.kts").exists() or (repo / "build.gradle").exists():
        return "android-gradle"
    if (repo / "Cargo.toml").exists():
        return "rust"
    if (repo / "go.mod").exists():
        return "go"
    if (repo / "CMakeLists.txt").exists():
        return "native-cmake"
    if (repo / "Makefile").exists():
        return "native-make"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_path", type=Path)
    ap.add_argument("--workdir", type=Path, default=None)
    args = ap.parse_args()

    repo = args.repo_path.resolve()
    if not repo.is_dir():
        print(f"ERROR: repo not found: {repo}", file=sys.stderr)
        return 2

    workdir = args.workdir or (Path("/home/z/my-project/scripts/_work") / repo.name)
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"[repo_analyze] target={repo}", file=sys.stderr)
    print(f"[repo_analyze] workdir={workdir}", file=sys.stderr)

    signals: list[dict] = []
    package_name = None
    version_name = None
    version_code = None
    shared_user_id = None

    project_type = identify_project_type(repo)
    print(f"[repo_analyze] project_type={project_type}", file=sys.stderr)

    # Manifest (Android project)
    manifest = find_manifest(repo)
    manifest_perms = []
    if manifest:
        package_name, manifest_perms, version_name, version_code, shared_user_id = parse_manifest(manifest)
        for p in manifest_perms:
            signals.append({
                "kind": "android_perm",
                "name": p,
                "source": f"repo:{manifest.relative_to(repo)}",
                "evidence": f"<uses-permission android:name=\"{p}\" />",
                "confidence": "unambiguous",
            })

    # C/C++ files
    c_files = find_files(repo, [".c", ".cpp", ".cc", ".h", ".hpp"])
    print(f"[repo_analyze] scanning {len(c_files)} C/C++ files...", file=sys.stderr)
    for f in c_files:
        signals.extend(scan_file(f, C_PATTERNS, "repo"))

    # JNI declarations (C/C++)
    for f in c_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            m = JNI_DECL_PATTERN.search(line)
            if m:
                signals.append({
                    "kind": "jni_entry",
                    "name": m.group(1),
                    "source": f"repo:{f.relative_to(repo)}:{line_no}",
                    "evidence": line.strip()[:200],
                    "confidence": "unambiguous",
                })

    # Java/Kotlin files
    jk_files = find_files(repo, [".java", ".kt"])
    print(f"[repo_analyze] scanning {len(jk_files)} Java/Kotlin files...", file=sys.stderr)
    for f in jk_files:
        signals.extend(scan_file(f, JAVA_PATTERNS, "repo"))
        # Native declarations
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            m = JAVA_NATIVE_PATTERN.search(line)
            if m:
                signals.append({
                    "kind": "jni_native_decl",
                    "name": f"native {line.strip()[:100]}",
                    "source": f"repo:{f.relative_to(repo)}:{line_no}",
                    "evidence": line.strip()[:200],
                    "confidence": "unambiguous",
                })

    # Go files
    go_files = find_files(repo, [".go"])
    print(f"[repo_analyze] scanning {len(go_files)} Go files...", file=sys.stderr)
    for f in go_files:
        signals.extend(scan_file(f, GO_PATTERNS, "repo"))

    # Rust files
    rs_files = find_files(repo, [".rs"])
    print(f"[repo_analyze] scanning {len(rs_files)} Rust files...", file=sys.stderr)
    for f in rs_files:
        signals.extend(scan_file(f, RUST_PATTERNS, "repo"))

    # Path signals
    print("[repo_analyze] scanning for hardcoded paths...", file=sys.stderr)
    signals.extend(scan_paths(repo))

    # De-duplicate identical (kind, name, source) entries
    seen = set()
    deduped = []
    for s in signals:
        key = (s["kind"], s["name"], s["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    findings = {
        "target": str(repo),
        "target_type": "repo",
        "project_type": project_type,
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "shared_user_id": shared_user_id,
        "manifest_path": str(manifest.relative_to(repo)) if manifest else None,
        "signals": deduped,
    }
    out_path = workdir / "findings.json"
    out_path.write_text(json.dumps(findings, indent=2))
    print(f"[repo_analyze] wrote {out_path} ({len(deduped)} signals)", file=sys.stderr)
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
