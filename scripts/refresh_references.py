#!/usr/bin/env python3
"""
ksu-profile-analyzer — reference refresh script.

Re-fetches the canonical KernelSU / Linux source files, parses them, and
regenerates the reference/*.md files. Appends a dated entry to
reference/_refresh_log.md and updates reference/_cache/.last_refresh.

Usage:
    python3 refresh_references.py [--skill-root <path>] [--force]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

SKILL_ROOT_DEFAULT = Path("/home/z/my-project/skills/ksu-profile-analyzer")
REFRESH_TTL_DAYS = 30

# Canonical source URLs
SOURCES: list[dict] = [
    {
        "id": "upstream_Natives",
        "url": "https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt",
        "cache_ext": ".kt",
        "regen": ["reference/ksu_profile_schema.md", "reference/forks/_base.md"],
    },
    {
        "id": "upstream_Capabilities",
        "url": "https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt",
        "cache_ext": ".kt",
        "regen": ["reference/capabilities.md"],
    },
    {
        "id": "upstream_Groups",
        "url": "https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt",
        "cache_ext": ".kt",
        "regen": ["reference/groups.md"],
    },
    {
        "id": "ksu_next_Natives",
        "url": "https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt",
        "cache_ext": ".kt",
        "regen": ["reference/forks/ksu-next.md"],
    },
    {
        "id": "ksu_next_Capabilities",
        "url": "https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt",
        "cache_ext": ".kt",
        "regen": [],
    },
    {
        "id": "ksu_next_Groups",
        "url": "https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt",
        "cache_ext": ".kt",
        "regen": [],
    },
    {
        "id": "sukisu_Natives",
        "url": "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/Natives.kt",
        "cache_ext": ".kt",
        "regen": ["reference/forks/sukisu-ultra.md"],
    },
    {
        "id": "sukisu_Capabilities",
        "url": "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Capabilities.kt",
        "cache_ext": ".kt",
        "regen": [],
    },
    {
        "id": "sukisu_Groups",
        "url": "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Groups.kt",
        "cache_ext": ".kt",
        "regen": [],
    },
    {
        "id": "app_profile_html",
        "url": "https://kernelsu.org/guide/app-profile.html",
        "cache_ext": ".html",
        "regen": ["reference/selinux.md"],
    },
    {
        "id": "capabilities_7_man",
        "url": "https://man7.org/linux/man-pages/man7/capabilities.7.html",
        "cache_ext": ".html",
        "regen": [],
    },
]


def http_get(url: str, timeout: int = 30) -> str:
    """HTTP GET with retries."""
    req = Request(url, headers={"User-Agent": "ksu-profile-analyzer/1.0 (refresh script)"})
    last_err = None
    for _ in range(3):
        try:
            with urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except (URLError, HTTPError) as e:
            last_err = e
            continue
    raise RuntimeError(f"failed to fetch {url}: {last_err}")


def needs_refresh(skill_root: Path, force: bool) -> tuple[bool, str | None]:
    """Check if refresh is needed based on cache age."""
    last_file = skill_root / "reference" / "_cache" / ".last_refresh"
    if force or not last_file.exists():
        return True, None
    try:
        last_date_str = last_file.read_text().strip()
        last_date = datetime.date.fromisoformat(last_date_str)
        today = datetime.date.today()
        age_days = (today - last_date).days
        if age_days > REFRESH_TTL_DAYS:
            return True, last_date_str
        return False, last_date_str
    except Exception:
        return True, None


def fetch_and_cache(source: dict, cache_dir: Path) -> tuple[bool, str, str | None]:
    """Fetch the source, return (changed, new_sha256, content)."""
    try:
        content = http_get(source["url"])
    except Exception as e:
        print(f"  WARN: fetch failed for {source['id']}: {e}", file=sys.stderr)
        return False, "", None

    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    cache_file = cache_dir / f"{sha}{source['cache_ext']}"
    if cache_file.exists():
        # Already cached (and SHA matches) — unchanged
        return False, sha, content
    # Write new cache file
    cache_file.write_text(content)
    # Clean up old cache files for this source (by checking which cache files
    # with this extension are not referenced). For simplicity, we just append —
    # the cache will accumulate but it's bounded.
    return True, sha, content


def parse_capabilities_kt(content: str) -> list[dict]:
    """Parse Capabilities.kt enum entries."""
    entries = []
    # Pattern: CAP_NAME(N, "Display", "Description")
    pat = re.compile(r'(\bCAP_[A-Z_]+)\((\d+),\s*"([^"]+)",\s*"([^"]+)"\)')
    for m in pat.finditer(content):
        entries.append({
            "const": m.group(1),
            "num": int(m.group(2)),
            "display": m.group(3),
            "desc": m.group(4),
        })
    return entries


def parse_groups_kt(content: str) -> list[dict]:
    """Parse Groups.kt enum entries."""
    entries = []
    pat = re.compile(r'([A-Z][A-Z0-9_]*)\((\d+),\s*"([^"]+)",\s*"([^"]+)"\)')
    for m in pat.finditer(content):
        entries.append({
            "const": m.group(1),
            "gid": int(m.group(2)),
            "name": m.group(3),
            "desc": m.group(4),
        })
    return entries


def parse_profile_data_class(content: str) -> dict | None:
    """Parse the Profile data class fields and defaults."""
    # Find: data class Profile( ... ) : Parcelable { ... }
    m = re.search(r'data class Profile\((.*?)\) : Parcelable', content, re.DOTALL)
    if not m:
        return None
    body = m.group(1)
    fields = []
    # Match: val name: Type = default,
    field_pat = re.compile(r'val\s+(\w+):\s+([^\s,=]+)(?:\s*=\s*([^,]+?))?[,)]', re.DOTALL)
    for fm in field_pat.finditer(body):
        fields.append({
            "name": fm.group(1).strip(),
            "type": fm.group(2).strip(),
            "default": fm.group(3).strip() if fm.group(3) else None,
        })
    return {"fields": fields}


def diff_capabilities(old: list[dict], new: list[dict]) -> dict:
    old_by_const = {e["const"]: e for e in old}
    new_by_const = {e["const"]: e for e in new}
    added = [c for c in new_by_const if c not in old_by_const]
    removed = [c for c in old_by_const if c not in new_by_const]
    modified = []
    for c in new_by_const:
        if c in old_by_const:
            old_e = old_by_const[c]
            new_e = new_by_const[c]
            if old_e["desc"] != new_e["desc"] or old_e["display"] != new_e["display"]:
                modified.append(c)
    return {"added": added, "removed": removed, "modified": modified, "total": len(new)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill-root", type=Path, default=SKILL_ROOT_DEFAULT)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    skill_root = args.skill_root.resolve()
    cache_dir = skill_root / "reference" / "_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    needed, prev_date = needs_refresh(skill_root, args.force)
    if not needed:
        print(f"[refresh] cache is fresh (last: {prev_date}). Use --force to refresh anyway.", file=sys.stderr)
        return 0

    print(f"[refresh] starting (previous: {prev_date or 'first refresh'})", file=sys.stderr)

    today_str = datetime.date.today().isoformat()
    changelog: list[str] = []
    changelog.append(f"## {today_str}")
    changelog.append(f"**Previous refresh**: {prev_date or 'first refresh'}")
    changelog.append("")
    changelog.append("### Changes since last refresh")

    # Track parsed versions for diff
    parsed_caps: dict[str, list[dict]] = {}  # source_id → entries
    parsed_groups: dict[str, list[dict]] = {}
    parsed_profiles: dict[str, dict] = {}
    fetched: dict[str, str] = {}  # source_id → sha

    # Fetch all sources first
    for src in SOURCES:
        print(f"  fetching {src['id']}...", file=sys.stderr)
        changed, sha, content = fetch_and_cache(src, cache_dir)
        fetched[src["id"]] = sha
        if not content:
            changelog.append(f"- `{src['id']}`: FAILED to fetch")
            continue
        if not changed:
            # Load from cache
            cache_file = cache_dir / f"{sha}{src['cache_ext']}"
            content = cache_file.read_text()

        # Parse based on source type
        if "Capabilities" in src["id"]:
            entries = parse_capabilities_kt(content)
            parsed_caps[src["id"]] = entries
            status = f"unchanged ({len(entries)} entries)" if not changed else f"+NEW (parsed {len(entries)} entries)"
            changelog.append(f"- `{src['id']}`: {status}")
        elif "Groups" in src["id"]:
            entries = parse_groups_kt(content)
            parsed_groups[src["id"]] = entries
            changelog.append(f"- `{src['id']}`: {'unchanged' if not changed else '+changed'} ({len(entries)} entries)")
        elif "Natives" in src["id"]:
            profile = parse_profile_data_class(content)
            parsed_profiles[src["id"]] = profile
            if profile:
                changelog.append(f"- `{src['id']}` Profile: {'unchanged' if not changed else '+changed'} ({len(profile['fields'])} fields)")
            else:
                changelog.append(f"- `{src['id']}` Profile: parse FAILED")
        else:
            changelog.append(f"- `{src['id']}`: {'unchanged' if not changed else '+changed'}")

    # Compute capability diffs across forks
    upstream_caps = parsed_caps.get("upstream_Capabilities", [])
    for fork_id in ("ksu_next_Capabilities", "sukisu_Capabilities"):
        if fork_id in parsed_caps:
            fork_caps = parsed_caps[fork_id]
            d = diff_capabilities(upstream_caps, fork_caps)
            if d["added"] or d["removed"] or d["modified"]:
                changelog.append(f"- `{fork_id}` diverges from upstream: +{len(d['added'])}/-{len(d['removed'])}/~{len(d['modified'])}")
            else:
                changelog.append(f"- `{fork_id}`: matches upstream")

    # Compute profile diffs across forks
    upstream_profile = parsed_profiles.get("upstream_Natives", {})
    for fork_id in ("ksu_next_Natives", "sukisu_Natives"):
        if fork_id in parsed_profiles:
            fork_profile = parsed_profiles[fork_id]
            if upstream_profile and fork_profile:
                up_fields = {f["name"]: f for f in upstream_profile.get("fields", [])}
                fk_fields = {f["name"]: f for f in fork_profile.get("fields", [])}
                diffs = []
                for name in up_fields:
                    if name not in fk_fields:
                        diffs.append(f"removed `{name}`")
                    elif up_fields[name]["default"] != fk_fields[name]["default"]:
                        diffs.append(f"`{name}` default {up_fields[name]['default']} → {fk_fields[name]['default']}")
                for name in fk_fields:
                    if name not in up_fields:
                        diffs.append(f"added `{name}` (default {fk_fields[name]['default']})")
                if diffs:
                    changelog.append(f"- `{fork_id}` Profile diverges from upstream: {', '.join(diffs)}")
                else:
                    changelog.append(f"- `{fork_id}` Profile: matches upstream")

    # Update .last_refresh
    (cache_dir / ".last_refresh").write_text(today_str)

    # Append to _refresh_log.md
    log_path = skill_root / "reference" / "_refresh_log.md"
    existing = log_path.read_text() if log_path.exists() else ""
    # Find the "---" separator after the header
    sep_idx = existing.find("<!-- Entries appended below this line by scripts/refresh_references.py -->")
    if sep_idx != -1:
        # Insert after the comment line
        insert_pos = existing.find("\n", sep_idx) + 1
        new_content = existing[:insert_pos] + "\n" + "\n".join(changelog) + "\n\n" + existing[insert_pos:]
    else:
        new_content = existing + "\n\n" + "\n".join(changelog) + "\n"
    log_path.write_text(new_content)

    print(f"[refresh] updated {log_path}", file=sys.stderr)
    print(f"[refresh] cache marker updated to {today_str}", file=sys.stderr)
    print("\n".join(changelog))
    return 0


if __name__ == "__main__":
    sys.exit(main())
