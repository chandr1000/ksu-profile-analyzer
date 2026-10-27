# Pipeline: Reference refresh

Re-fetch the canonical KernelSU / Linux source files and regenerate the `reference/*.md` files. Runs silently when the cache is older than 30 days (or missing), and also runs on explicit user request ("refresh references", "update the cap/group tables").

## Inputs

- `force` (optional, default `false`): re-fetch even if cache is fresh.

## Trigger conditions

The skill checks `reference/_cache/.last_refresh` (ISO date string, e.g. `2026-09-15`). Refresh runs if:

- `.last_refresh` is missing, OR
- Today's date - `.last_refresh` date > 30 days, OR
- User explicitly requested refresh, OR
- `force=true` was passed.

## Sources fetched

| URL | Target file | Parser |
|---|---|---|
| `https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt` | `reference/_cache/<sha256>.kt` → regenerates `reference/ksu_profile_schema.md` | Regex extract of `data class Profile`, `enum class RootProfileFlag`, `enum class Namespace`, constants |
| `https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt` | `reference/_cache/<sha256>.kt` → regenerates `reference/capabilities.md` | Regex extract of `CAP_*` enum entries |
| `https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt` | `reference/_cache/<sha256>.kt` → regenerates `reference/groups.md` | Regex extract of GID enum entries |
| `https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt` | (cached, diffed against upstream) → updates `reference/forks/ksu-next.md` | Same parser, diff against upstream |
| `https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt` | (diffed against upstream) | Same parser |
| `https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt` | (diffed against upstream) | Same parser |
| `https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/Natives.kt` | (cached, diffed against upstream) → updates `reference/forks/sukisu-ultra.md` | Same parser |
| `https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Capabilities.kt` | (diffed) | Same parser |
| `https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Groups.kt` | (diffed) | Same parser |
| `https://kernelsu.org/guide/app-profile.html` | `reference/_cache/<sha256>.html` → regenerates `reference/selinux.md` | HTML → text extraction (use Python `html.parser` or `beautifulsoup` if available) |
| `https://man7.org/linux/man-pages/man7/capabilities.7.html` | (cached) — informational only; the `Capabilities.kt` source is authoritative for the skill | HTML → text extraction |

## Refresh algorithm

For each source URL:

1. **Fetch** with `curl -fsSL --retry 3 --max-time 30`.
2. **Hash** the response body with SHA-256.
3. **Cache** at `reference/_cache/<sha256>.<ext>`.
4. **Compare** against the previous cached version (if any):
   - If SHA-256 matches → "unchanged"
   - If SHA-256 differs → parse the new content and regenerate the corresponding `reference/*.md` file(s), recording what changed (new entries, removed entries, modified descriptions).
5. **Append** a dated entry to `reference/_refresh_log.md` summarizing the changes.
6. **Update** `reference/_cache/.last_refresh` with today's date.

## What gets regenerated

| Source changed | Files regenerated |
|---|---|
| upstream `Natives.kt` | `reference/ksu_profile_schema.md`, `reference/forks/_base.md` |
| upstream `Capabilities.kt` | `reference/capabilities.md` |
| upstream `Groups.kt` | `reference/groups.md` |
| upstream + KSU-Next `Natives.kt` (same SHA) | nothing new (fork matches upstream) — `reference/forks/ksu-next.md` notes "schema identical to upstream" |
| KSU-Next `Natives.kt` diverges | `reference/forks/ksu-next.md` updated with the new fields, `reference/forks/_diff_table.md` matrix updated |
| SukiSU-Ultra `Natives.kt` diverges | `reference/forks/sukisu-ultra.md` updated, `_diff_table.md` updated |
| `app-profile.html` changes | `reference/selinux.md` regenerated |
| `capabilities(7)` man page changes | informational note in `_refresh_log.md`; the `Capabilities.kt` source is authoritative |

## Cache directory layout

```
reference/_cache/
├── .last_refresh                 # ISO date "YYYY-MM-DD"
├── <sha256_of_upstream_Natives.kt>.kt
├── <sha256_of_upstream_Capabilities.kt>.kt
├── <sha256_of_upstream_Groups.kt>.kt
├── <sha256_of_ksu_next_Natives.kt>.kt
├── <sha256_of_ksu_next_Capabilities.kt>.kt
├── <sha256_of_ksu_next_Groups.kt>.kt
├── <sha256_of_sukisu_Natives.kt>.kt
├── <sha256_of_sukisu_Capabilities.kt>.kt
├── <sha256_of_sukisu_Groups.kt>.kt
├── <sha256_of_app-profile.html>.html
└── <sha256_of_capabilities_7.html>.html
```

## Caching & idempotency

- If the fetched content's SHA-256 matches the cached version, the refresh skips re-parsing — "unchanged" entry in the log.
- If `curl` fails (network error, 404), the refresh aborts with a clear error and keeps the existing references intact. The skill continues using the (potentially stale) cached references — better stale than broken.
- The refresh is **idempotent**: re-running it produces the same output if nothing changed upstream.

## Output (the changelog footer in analysis.md)

When refresh ran during this skill invocation, the `analysis.md` file gets a section appended at the **far end** (after the ambiguous-findings section, after the strace helper section if present):

```markdown
---
## Reference Refresh Changelog
**Auto-refreshed on**: 2026-10-28
**Previous refresh**: 2026-09-15

### Changes since last refresh
- `Capabilities.kt` (upstream): +0 / -0 / unchanged (40 entries)
- `Capabilities.kt` (KSU-Next): +0 / -0 / unchanged (matches upstream)
- `Capabilities.kt` (SukiSU-Ultra): +0 / -0 / unchanged (matches upstream)
- `Groups.kt` (upstream): +2 (NEW_GID_X=1096, NEW_GID_Y=1097) / -0
- `Groups.kt` (KSU-Next): +0 / -0 / unchanged (matches upstream)
- `Groups.kt` (SukiSU-Ultra): +0 / -0 / unchanged (matches upstream)
- `Natives.kt` Profile (upstream): 1 field default changed (`flags` 1L → 3L)
- `Natives.kt` Profile (KSU-Next): unchanged
- `Natives.kt` Profile (SukiSU-Ultra): unchanged
- `app-profile.html`: 1 paragraph edited in SELinux section
- `capabilities(7)`: +1 new cap `CAP_NEW_THING` (since Linux 6.16) — note: not yet in KernelSU's table
```

If nothing changed, the section reads:

```markdown
---
## Reference Refresh Changelog
**Auto-refreshed on**: 2026-10-28
**Previous refresh**: 2026-10-15

No changes since last refresh.
```

## Failure modes

| Failure | Behavior |
|---|---|
| One URL 404s | Log the failure, continue with the others, regenerate only the files whose sources succeeded. Note in changelog: "FAILED to fetch <URL>: 404" |
| All URLs fail | Abort refresh, log "All sources unreachable; keeping cached references. Last good refresh: <date>". Continue the skill with cached references. |
| Parser fails on a source | Log the parser error, keep the previous version of the regenerated file. Note in changelog: "FAILED to parse <source>: <error>" |
| `reference/_cache/` not writable | Abort refresh, log "Cache directory not writable". Continue with cached references. |
