#!/usr/bin/env python3
"""
ksu-profile-analyzer — APK analysis pipeline.

Usage:
    python3 apk_analyze.py <apk_path> [--workdir <dir>] [--jadx-path <jadx>] [--apktool-path <apktool>]

Outputs a findings.json file in the workdir (default: /home/z/my-project/scripts/_work/<apk_basename>/findings.json).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

# Permission → groups/caps mapping (mirrors reference/syscall_to_cap.md AndroidManifest section)
ANDROID_PERM_MAP: dict[str, dict] = {
    "android.permission.INTERNET": {"groups": [3003], "caps": [], "confidence": "unambiguous"},
    "android.permission.CHANGE_NETWORK_STATE": {"groups": [3005], "caps": ["CAP_NET_ADMIN"], "confidence": "unambiguous"},
    "android.permission.CHANGE_WIFI_STATE": {"groups": [3005], "caps": ["CAP_NET_ADMIN"], "confidence": "unambiguous"},
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": {"groups": [3005], "caps": [], "confidence": "unambiguous"},
    "android.permission.BLUETOOTH": {"groups": [3002], "caps": [], "confidence": "unambiguous"},
    "android.permission.BLUETOOTH_ADMIN": {"groups": [3001], "caps": [], "confidence": "unambiguous"},
    "android.permission.READ_EXTERNAL_STORAGE": {"groups": [1028], "caps": [], "confidence": "unambiguous"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"groups": [1015, 1023], "caps": [], "confidence": "unambiguous"},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"groups": [1077], "caps": [], "confidence": "unambiguous"},
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": {"groups": [1009], "caps": ["CAP_SYS_ADMIN"], "confidence": "unambiguous"},
    "android.permission.WAKE_LOCK": {"groups": [3010], "caps": [], "confidence": "unambiguous"},
    "android.permission.READ_LOGS": {"groups": [1007], "caps": [], "confidence": "unambiguous"},
    "android.permission.NFC": {"groups": [1027], "caps": [], "confidence": "unambiguous"},
    "android.permission.SET_TIME": {"groups": [], "caps": ["CAP_SYS_TIME"], "confidence": "unambiguous"},
    "android.permission.SET_TIME_ZONE": {"groups": [], "caps": ["CAP_SYS_TIME"], "confidence": "ambiguous"},
}

# Regex for su invocation in Java/smali
SU_PATTERNS = [
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\(\s*"su"'), "Runtime.exec(\"su\")", "unambiguous"),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\(\s*new\s+String\[\]\s*\{\s*"su"'), "Runtime.exec({\"su\",...})", "unambiguous"),
    (re.compile(r'ProcessBuilder\(\s*(?:new\s+String\[\]\s*\{)?\s*"su"'), "ProcessBuilder(\"su\")", "unambiguous"),
    (re.compile(r'Lcom/topjohnwu/superuser/Shell;->su\b'), "Shell.su (libsu)", "unambiguous"),
    (re.compile(r'Lcom/topjohnwu/superuser/Shell;->cmd\b'), "Shell.cmd (libsu)", "unambiguous"),
    (re.compile(r'Lcom/topjohnwu/magisk/MagiskBean'), "MagiskBean", "unambiguous"),
    (re.compile(r'"\s*/system/(?:x?bin|sbin)/su\b'), "string path /system/.../su", "unambiguous"),
    (re.compile(r'"\s/sbin/su\b'), "string path /sbin/su", "unambiguous"),
]

# Path → caps/groups mapping
PATH_MAP = {
    "/dev/mem": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/dev/kmem": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/proc/kcore": {"caps": ["CAP_SYS_RAWIO"], "groups": [], "confidence": "unambiguous"},
    "/dev/uhid": {"caps": [], "groups": [3011], "confidence": "unambiguous"},
    "/sys/kernel/debug/": {"caps": ["CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "ambiguous"},
    "/sys/kernel/tracing/": {"caps": ["CAP_SYS_ADMIN", "CAP_PERFMON"], "groups": [3012], "confidence": "ambiguous"},
    "/data/adb/ksu/": {"caps": ["CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/data/adb/modules/": {"caps": ["CAP_DAC_READ_SEARCH"], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/xbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/bin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/system/sbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
    "/sbin/su": {"caps": [], "groups": [], "confidence": "unambiguous", "sets_allow_su": True},
}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, check=kw.pop("check", False), capture_output=True, text=True, **kw)


def extract_manifest_permissions(apk: Path, workdir: Path) -> list[str]:
    """Extract declared permissions from AndroidManifest.xml via aapt2 (fast path)."""
    out = run(["aapt2", "dump", "permissions", str(apk)], cwd=workdir)
    if out.returncode == 0:
        perms = []
        for line in out.stdout.splitlines():
            m = re.match(r"\s*(android\.permission\.\S+)", line)
            if m:
                perms.append(m.group(1).strip())
        if perms:
            return sorted(set(perms))
    # Fallback: aapt (older)
    out = run(["aapt", "dump", "permissions", str(apk)], cwd=workdir)
    perms = []
    for line in out.stdout.splitlines():
        m = re.match(r"\s*(android\.permission\.\S+)", line)
        if m:
            perms.append(m.group(1).strip())
    return sorted(set(perms))


def decode_apk(apk: Path, workdir: Path) -> Path | None:
    """Run apktool to decode smali + resources."""
    decoded = workdir / "decoded"
    if decoded.exists():
        shutil.rmtree(decoded)
    out = run(["apktool", "d", "-f", "-o", str(decoded), str(apk)], cwd=workdir)
    if out.returncode != 0:
        print(f"  apktool failed: {out.stderr}", file=sys.stderr)
        return None
    return decoded


def extract_native_libs(apk: Path, workdir: Path) -> list[Path]:
    """Extract lib/<abi>/*.so files from the APK."""
    native_dir = workdir / "native_libs"
    if native_dir.exists():
        shutil.rmtree(native_dir)
    native_dir.mkdir()
    libs: list[Path] = []
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                # Extract preserving the lib/<abi>/<name> structure
                target = native_dir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(name) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                libs.append(target)
    return libs


def scan_smali_for_su(decoded: Path) -> list[dict]:
    """Scan decoded smali for su invocation patterns."""
    signals = []
    smali_dirs = [d for d in decoded.iterdir() if d.is_dir() and d.name.startswith("smali")]
    for sd in smali_dirs:
        for path in sd.rglob("*.smali"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = path.relative_to(decoded)
            for pat, name, conf in SU_PATTERNS:
                for m in pat.finditer(text):
                    line_no = text[:m.start()].count("\n") + 1
                    signals.append({
                        "kind": "su_invocation",
                        "name": name,
                        "source": f"apk:{rel}:{line_no}",
                        "evidence": m.group(0).strip(),
                        "confidence": conf,
                    })
    return signals


def scan_strings_for_paths(decoded: Path, native_libs_dir: Path) -> list[dict]:
    """Scan resource strings + native lib strings for interesting paths."""
    signals = []
    seen = set()

    # Resource strings (strings.xml)
    res_dirs = list((decoded / "res").glob("values*")) if (decoded / "res").exists() else []
    for rd in res_dirs:
        strings_xml = rd / "strings.xml"
        if not strings_xml.exists():
            continue
        try:
            text = strings_xml.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for path_prefix in ("/dev/", "/proc/", "/sys/", "/data/adb/", "/system/xbin/", "/system/bin/", "/system/sbin/", "/sbin/"):
            for m in re.finditer(re.escape(path_prefix) + r"[A-Za-z0-9_./-]+", text):
                p = m.group(0).rstrip('"').rstrip("'")
                if p in seen:
                    continue
                seen.add(p)
                signals.append({
                    "kind": "file_path",
                    "name": p,
                    "source": f"apk:res/{rd.name}/strings.xml",
                    "evidence": f"string: {p}",
                    "confidence": "ambiguous",
                })

    # Native lib strings (via `strings -a`)
    for lib in native_libs_dir.rglob("*.so") if native_libs_dir.exists() else []:
        try:
            out = run(["strings", "-a", "-n", "4", str(lib)])
            text = out.stdout
        except Exception:
            continue
        rel = lib.relative_to(native_libs_dir.parent)
        for path_prefix in ("/dev/", "/proc/", "/sys/", "/data/adb/", "/system/xbin/", "/system/bin/", "/system/sbin/", "/sbin/"):
            for m in re.finditer(re.escape(path_prefix) + r"[A-Za-z0-9_./-]+", text):
                p = m.group(0).strip()
                if p in seen:
                    continue
                seen.add(p)
                signals.append({
                    "kind": "file_path",
                    "name": p,
                    "source": f"apk:{rel}",
                    "evidence": "string table",
                    "confidence": "ambiguous",
                })

    return signals


def parse_manifest_for_package(decoded: Path) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract package name, version_name, version_code, shared_user_id from manifest."""
    manifest = decoded / "AndroidManifest.xml" if decoded.exists() else None
    if manifest is None or not manifest.exists():
        return None, None, None, None
    text = manifest.read_text(encoding="utf-8", errors="ignore")
    pkg_m = re.search(r'package="([^"]+)"', text)
    pkg = pkg_m.group(1) if pkg_m else None
    vn_m = re.search(r'versionName="([^"]*)"', text)
    vn = vn_m.group(1) if vn_m else None
    vc_m = re.search(r'versionCode="(\d+)"', text)
    vc = vc_m.group(1) if vc_m else None
    su_m = re.search(r'sharedUserId="([^"]+)"', text)
    su = su_m.group(1) if su_m else None
    return pkg, vn, vc, su


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk_path", type=Path)
    ap.add_argument("--workdir", type=Path, default=None,
                    help="Working directory (default: /home/z/my-project/scripts/_work/<apk_basename>)")
    args = ap.parse_args()

    apk = args.apk_path.resolve()
    if not apk.is_file():
        print(f"ERROR: APK not found: {apk}", file=sys.stderr)
        return 2

    workdir = args.workdir or (Path("/home/z/my-project/scripts/_work") / apk.stem)
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"[apk_analyze] target={apk}", file=sys.stderr)
    print(f"[apk_analyze] workdir={workdir}", file=sys.stderr)

    signals: list[dict] = []

    # 1. Manifest permissions
    print("[apk_analyze] extracting manifest permissions...", file=sys.stderr)
    perms = extract_manifest_permissions(apk, workdir)
    for p in perms:
        info = ANDROID_PERM_MAP.get(p, {"groups": [], "caps": [], "confidence": "unambiguous"})
        signals.append({
            "kind": "android_perm",
            "name": p,
            "source": "manifest",
            "evidence": f"<uses-permission android:name=\"{p}\" />",
            "confidence": info["confidence"],
        })

    # 2. Decode APK (smali + resources)
    print("[apk_analyze] decoding APK with apktool...", file=sys.stderr)
    decoded = decode_apk(apk, workdir)

    package_name = version_name = version_code = shared_uid = None
    if decoded:
        package_name, version_name, version_code, shared_uid = parse_manifest_for_package(decoded)
        print(f"[apk_analyze] package={package_name} version={version_name}/{version_code} sharedUserId={shared_uid}", file=sys.stderr)

        # 3. Scan smali for su invocations
        print("[apk_analyze] scanning smali for su invocations...", file=sys.stderr)
        signals.extend(scan_smali_for_su(decoded))

        # 4. Scan strings for paths
        native_libs_dir = workdir / "native_libs"
        print("[apk_analyze] scanning strings for paths...", file=sys.stderr)
        signals.extend(scan_strings_for_paths(decoded, native_libs_dir))

    # 5. Extract native libs and recurse into binary pipeline
    print("[apk_analyze] extracting native libs...", file=sys.stderr)
    libs = extract_native_libs(apk, workdir)
    if libs:
        print(f"[apk_analyze] found {len(libs)} native libs; dispatching to binary_analyze.py", file=sys.stderr)
        for lib in libs:
            rel = lib.relative_to((workdir / "native_libs"))
            source_tag = f"apk:lib/{rel.as_posix()}"
            r = run([
                sys.executable,
                str(Path(__file__).parent / "binary_analyze.py"),
                str(lib),
                "--parent-source", source_tag,
                "--workdir", str(workdir / "binary_findings" / lib.name),
            ])
            findings_path = workdir / "binary_findings" / lib.name / "findings.json"
            if findings_path.exists():
                try:
                    bf = json.loads(findings_path.read_text())
                    signals.extend(bf.get("signals", []))
                except Exception as e:
                    print(f"  WARN: failed to read binary findings for {lib.name}: {e}", file=sys.stderr)

    # 6. Emit findings.json
    findings = {
        "target": str(apk),
        "target_type": "apk",
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "shared_user_id": shared_uid,
        "signals": signals,
    }
    out_path = workdir / "findings.json"
    out_path.write_text(json.dumps(findings, indent=2))
    print(f"[apk_analyze] wrote {out_path} ({len(signals)} signals)", file=sys.stderr)
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
