# Reference Refresh Changelog

This file is append-only. Each refresh run appends a dated entry.

The `scripts/refresh_references.py` script:
1. Fetches the upstream sources (see `pipelines/refresh.md` for the URL list)
2. Parses each source and regenerates `reference/capabilities.md`, `reference/groups.md`, `reference/ksu_profile_schema.md`, `reference/selinux.md`, `reference/forks/*.md`
3. Diffs against the previous versions (cached in `reference/_cache/`)
4. Appends a dated entry to this file showing what changed

If this file has only the header (no dated entries below), the references have never been refreshed — the skill ships with hand-authored initial versions, and the first refresh will establish a baseline.

The skill checks `reference/_cache/.last_refresh` (ISO date string) on each invocation. If older than 30 days (or missing), it silently runs `refresh_references.py` before proceeding with analysis.

## Format

```
## YYYY-MM-DD
**Previous refresh**: YYYY-MM-DD (or "first refresh")

### Changes since last refresh
- `Capabilities.kt`: +N / -N / unchanged (total entries: N)
- `Groups.kt`: +N / -N / unchanged (total entries: N)
- `Natives.kt` Profile: <summary of field changes>
- `app-profile.html`: <summary of doc edits>
- `capabilities(7)`: <summary of man page changes>

### Fork-specific
- `ksu-next/Natives.kt`: ...
- `sukisu-ultra/Natives.kt`: ...

### Cache state
- Files cached in `reference/_cache/` with SHA256 names
- Last refresh marker: `reference/_cache/.last_refresh` updated to YYYY-MM-DD
```

---

<!-- Entries appended below this line by scripts/refresh_references.py -->
