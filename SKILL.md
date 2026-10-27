---
name: ksu-profile-analyzer
description: |
  Analyze an Android APK, native ELF binary, or source repo and generate a least-privilege KernelSU App Profile that confines the target with only the privileges it actually needs. Use this skill whenever the user asks to "confine", "sandbox", "restrict", "profile", "grant minimum privileges to", or "generate a KSU/KernelSU app profile for" an Android app, APK, .so library, ELF executable, or project source. Also use it when the user mentions KernelSU, KSU-Next, SukiSU-Ultra, "app profile", "root profile", "capability", "CAP_*", "Linux capabilities" in the context of restricting a specific Android app or binary. Strongly prefer this skill over generic reverse-engineering flows whenever the end goal is a KernelSU-family profile JSON. Supports minimal/recommended modes, two-pass interactive refinement, runtime strace fallback, automatic 30-day reference refresh, and per-fork output bundles (upstream KernelSU, KernelSU-Next, SukiSU-Ultra).
---

# ksu-profile-analyzer

Generate a **least-privilege KernelSU App Profile** that confines a target (Android APK, ELF binary, or source repo) to only the privileges it actually needs. The skill is offline/audit-only by default — it never calls `ksud` to apply anything; it emits an apply script the user reviews and runs by hand.

## When to use

Trigger this skill when the user says things like:

- "Generate a KSU profile for `<app>`"
- "Confine `<app>` with the minimum privileges it needs"
- "What capabilities does `<binary>` actually use? Write a KernelSU profile for it."
- "Reverse engineer this APK and produce a least-privilege root profile"
- "Restrict `<app>` on KernelSU-Next / SukiSU-Ultra"

Do not trigger for generic "what is KernelSU" questions, or for unrelated reverse-engineering tasks where the user does not want a profile as the final deliverable.

## Output bundle layout

Every successful run produces a directory under `/home/z/my-project/download/ksu_profile_<pkg_or_basename>/` containing:

```
profile.kernelsu.json        # upstream KernelSU Profile (canonical)
profile.ksu-next.json        # KernelSU-Next variant (same schema, different target_fork)
profile.sukisu-ultra.json    # SukiSU-Ultra variant (same schema, different target_fork)
analysis.md                  # human-readable findings + ambiguous-finding Q&A + changelog footer
apply.kernelsu.sh            # audit-only apply script (NEVER auto-run)
apply.ksu-next.sh
apply.sukisu-ultra.sh
strace_capture.sh            # adb-pushable helper for runtime syscall capture (only when needed)
findings.json                # raw signals extracted (debugging / 2nd-pass input)
```

The 3 profile JSONs are byte-identical except for `target_fork` and the `_meta` block — all three KSU-family forks share the same canonical `Profile` data class. See `reference/forks/_diff_table.md` for the rationale.

## End-to-end workflow

### Stage 1 — Detect target type

Inspect the `target` argument:

- **APK**: ZIP magic + contains `AndroidManifest.xml` → run `pipelines/apk.md`
- **ELF**: file magic `\x7fELF` → run `pipelines/binary.md`
- **Directory with source files** (`.git/`, `*.kt`, `*.java`, `*.c`, `*.rs`, `*.go`, etc.) → run `pipelines/repo.md`
- **HTTP(S) git URL** → `git clone --depth 1` to a temp dir under `/home/z/my-project/scripts/_work/`, then treat as repo

If the target is an APK, also recursively run `pipelines/binary.md` against every `lib/<abi>/*.so` inside the APK — those are first-class targets whose syscalls contribute to the final capability set.

### Stage 2 — Dispatch pipeline(s)

For each pipeline, read the matching `pipelines/<name>.md` file before doing the work — these files contain the exact tool invocations, parsing rules, and signal-to-finding mappings. The three static pipelines (apk, binary, repo) emit a common `Findings` JSON shape:

```json
{
  "target": "<path>",
  "target_type": "apk|elf|repo",
  "package_name": "<com.foo.bar or null>",
  "signals": [
    { "kind": "syscall", "name": "mount", "source": "binary:libfoo.so", "evidence": "imported symbol" },
    { "kind": "android_perm", "name": "INTERNET", "source": "manifest", "evidence": "<uses-permission android:name=\"android.permission.INTERNET\" />" },
    { "kind": "file_path", "name": "/dev/mem", "source": "binary:libfoo.so", "evidence": "string table" },
    { "kind": "su_invocation", "name": "Runtime.exec(\"su\")", "source": "apk:classes.dex", "evidence": "Lcom/example/RootHelper;->exec()V" }
  ]
}
```

### Stage 3 — Aggregate findings

Merge all pipeline outputs into a single `findings.json` (with `source` tags preserved). De-duplicate identical signals from different sources (e.g. `mount` imported by both `libfoo.so` and `libbar.so` → one entry with two source tags).

### Stage 4 — Map findings to privileges

Use `reference/syscall_to_cap.md` as the authoritative mapping table. Each signal maps to:

- Zero or more `CAP_*` capabilities (from `reference/capabilities.md`)
- Zero or more Android GIDs (from `reference/groups.md`)
- A SELinux `context` and optional `rules` block (default `u:r:ksu:s0`, empty rules)
- A `namespace` value (default `INHERITED` = 0)
- A `flags` bitmask (default `1` = NO_NEW_PRIVS, always set for hardening)

Signals with **multiple possible mappings** or where static evidence is **suspected but not verified** (e.g. a `mount` import with no static call site found) are flagged for the ambiguous-findings list (see Stage 5).

### Stage 5 — Emit output bundle

Generate the 3 profile JSONs (only `target_fork` and `_meta` differ), the analysis.md (see template `templates/analysis_report.md.j2`), and the 3 apply scripts (see `templates/apply.sh.j2`). Include `strace_capture.sh` only if any ambiguous findings exist (see Stage 6).

### Stage 6 — Two-pass interactive refinement loop

This is built into the workflow, not skipped:

**Pass 1 (automatic):** Run Stages 1–5. The resulting `analysis.md` includes a clearly-delimited section titled **"⚠️ Ambiguous findings — please confirm"** with a numbered yes/no list. Each entry has:

- The signal (e.g. "Binary imports `mount` from libc, but no static call site found")
- The capability/group it would imply (e.g. `CAP_SYS_ADMIN`)
- A severity hint (low / medium / high)
- A yes/no question for the user

The first-pass `profile.*.json` files reflect **only signals with unambiguous evidence** — ambiguous caps stay OUT until the user confirms. This is the safe-by-default behavior.

**Pass 2 (interactive):** Wait for the user to reply. Parse responses like "yes to #2 and #5, no to #3" (free-form OK — the LLM interprets). For each confirmed signal, add the corresponding capability/group to all 3 profile JSONs, and append a "✅ Confirmed by user" note in `analysis.md` next to the corresponding item. For each denied signal, append "❌ Denied by user — kept out of profile". Re-emit the 3 JSONs.

If the user requests additional privileges not in the findings (e.g. "also add CAP_SYS_NICE"), add them and document the addition as "✅ User-requested addition".

### Stage 7 — Reference refresh (automatic, 30-day TTL)

Before Stage 1, check `reference/_cache/.last_refresh`. If older than 30 days (or missing), silently invoke `scripts/refresh_references.py`. This re-fetches:

- `tiann/KernelSU` — `Natives.kt`, `profile/Capabilities.kt`, `profile/Groups.kt`
- `KernelSU-Next/KernelSU-Next` — same files
- `SukiSU-Ultra/SukiSU-Ultra` — same files (under `com/sukisu/ultra/...`)
- `kernelsu.org/guide/app-profile.html` (SELinux rules syntax)
- `man7.org/linux/man-pages/man7/capabilities.7.html`

Refresh results are written to:

- `reference/_cache/` (cached source files, SHA256-named)
- `reference/_refresh_log.md` (append-only changelog)
- `reference/capabilities.md`, `reference/groups.md`, `reference/ksu_profile_schema.md`, `reference/selinux.md`, `reference/forks/*.md` (regenerated)

After refresh, append a "Reference Refresh Changelog" section to the **far end** of the same `analysis.md` the user is about to read, showing what changed since the last refresh:

```markdown
---
## Reference Refresh Changelog
**Auto-refreshed on**: 2026-10-28
**Previous refresh**: 2026-09-15

### Changes since last refresh
- `Capabilities.kt`: +0 / -0 / unchanged (40 entries)
- `Groups.kt`: +2 (NEW_GID_X=1096, NEW_GID_Y=1097) / -0
- `Natives.kt` Profile: 1 field default changed (`flags` 1L → 3L)
- `app-profile.html`: 1 paragraph edited in SELinux section
- `capabilities(7)`: +1 new cap `CAP_NEW_THING` (Linux 6.x)
```

If nothing changed: "No changes since last refresh on YYYY-MM-DD." (still log the run).

## Fork detection hint (top of every analysis.md)

The very first section of every `analysis.md` is a one-liner helping the user identify which fork they're running:

```
## Which fork are you running?
Run on device:  adb shell ls /data/adb/ | grep -E 'ksu|ksnd|sukid'
  - `ksud`  → KernelSU (upstream)        → apply.kernelsu.sh
  - `ksnd`  → KernelSU-Next              → apply.ksu-next.sh
  - `sukid` → SukiSU-Ultra              → apply.sukisu-ultra.sh
(All three forks currently share the same Profile schema, so the JSONs
are byte-identical apart from `target_fork` and `_meta`. Pick the one
matching your installed daemon.)
```

Daemon names are confirmed during the refresh pass — see `reference/forks/_diff_table.md`.

## SELinux policy (default = inherited)

By default, the emitted Profile uses:

- `context = "u:r:ksu:s0"` (inherited from the kernel's ksu domain)
- `rules = ""` (empty)

A stricter alternative is a custom SELinux domain per app (`u:r:app_<pkg>:s0`). **Do not auto-emit a custom domain.** SELinux denials fail silently and are painful to debug. Only suggest it in `analysis.md` as an opt-in:

> If you want stricter SELinux isolation, ask me to add a custom domain. I'll generate the rules and link `reference/troubleshoot_selinux.md` for debugging help.

If the user opts in (in Pass 2), generate rules:
```
type app_<sanitized_pkg>
enforce app_<sanitized_pkg>
typeattribute app_<sanitized_pkg> mlstrustedsubject
allow app_<sanitized_pkg> * * *
```
with `context = "u:r:app_<sanitized_pkg>:s0"` and link the troubleshoot file at the bottom of `analysis.md`.

## Strace runtime fallback

When any pipeline reports **packed/obfuscated binary** or **ambiguous syscalls** (a `mount` import with no call site, a stripped binary without dynamic symbols, etc.), include `strace_capture.sh` in the bundle and add a "🔬 Runtime Trace Helper" section to `analysis.md` explaining what the file is, why it's needed, and how to use it (push to device, run under su, pull logs back, re-invoke skill with `--from-strace ./strace_logs/`).

The re-analysis path is `pipelines/strace.md`, which parses strace output files and feeds them through the **same** `syscall_to_cap.md` mapping as the static pipelines. Findings from strace are tagged `source: "strace"` in `findings.json` so `analysis.md` can show what came from runtime vs static.

## The `currentUid` field

The Profile schema requires `currentUid` (the actual installed UID of the app on the device, in the `10000`–`19999` range for normal apps). Static analysis cannot know this.

**Default handling**: emit `currentUid: 0` as a placeholder in all 3 JSONs, and add a clearly-marked step in `analysis.md`:

> 📋 Look up the real UID on-device: `adb shell pm list packages -U | grep <pkg>`
> Reply with the UID in chat and I'll patch the JSON, or edit it yourself before applying.

If the user replies with a UID, patch all 3 JSONs and append a "✅ UID filled in" note in `analysis.md`.

## Hard rules (do not violate)

1. **Never auto-run `ksud` / `ksnd` / `sukid`.** The apply scripts ship as `.sh` files with a `# review-before-run` banner at the top. The skill's job is to emit them; the user's job is to read and run them.
2. **Never grant `CAP_SYS_ADMIN` by default.** It is "the new root" (per the Linux capabilities man page). Only include it when an unambiguous `mount`/`pivot_root`/`setns`/`swapon`/`sethostname`/`clone(CLONE_NEW*)` signal is found, OR the user confirms an ambiguous `mount`-import signal in Pass 2.
3. **Always set `flags = 1`** (NO_NEW_PRIVS) for hardening.
4. **Always default `umountModules = true`** for the non-root profile of any app that does NOT need module visibility (most apps).
5. **Never include `rootTemplate` unless the user explicitly references a saved template name.**
6. **Never emit `allowSu = true` unless the user asked for a root profile.** For apps that should NOT get root (e.g. banking apps to harden against root-detection), emit `allowSu: false` + `umountModules: true` + `nonRootUseDefault: false`.
7. **All scripts persist under `/home/z/my-project/scripts/`** before execution (Script Persistence Rule).
8. **All deliverables persist under `/home/z/my-project/download/`.** Never write outside this base path.

## Reference file map

When the workflow needs detail, load these files completely before proceeding:

| File | Read when you need to |
|---|---|
| `reference/ksu_profile_schema.md` | Confirm the exact field names, defaults, and types of the `Profile` data class |
| `reference/capabilities.md` | Map a CAP_* name to its kernel semantics |
| `reference/groups.md` | Map an Android GID to its kernel semantics |
| `reference/selinux.md` | Generate SELinux `context` / `rules` for a custom domain |
| `reference/syscall_to_cap.md` | Map a syscall, imported symbol, or Android permission to capabilities + groups |
| `reference/troubleshoot_selinux.md` | User opted into custom SELinux domain and the app is misbehaving |
| `reference/forks/_base.md` | Upstream KernelSU canonical schema |
| `reference/forks/ksu-next.md` | KSU-Next specifics (manager-level differences, same schema) |
| `reference/forks/sukisu-ultra.md` | SukiSU-Ultra specifics (manager-level differences, same schema) |
| `reference/forks/_diff_table.md` | Quick side-by-side comparison across forks |
| `pipelines/apk.md` | Analyzing an APK target |
| `pipelines/binary.md` | Analyzing an ELF (.so / executable) target |
| `pipelines/repo.md` | Analyzing a source repo target |
| `pipelines/strace.md` | Re-analyzing from runtime strace logs |
| `pipelines/refresh.md` | Refreshing reference data from upstream sources |
| `templates/profile_minimal.json` | Skeleton for minimal mode |
| `templates/profile_recommended.json` | Skeleton for recommended mode |
| `templates/analysis_report.md.j2` | Jinja2 template for analysis.md |
| `templates/apply.sh.j2` | Jinja2 template for the apply scripts |
| `templates/strace_capture.sh` | Pre-built adb-pushable helper |

## Modes

- **`minimal`** (default): only capabilities/groups with unambiguous evidence in Pass 1. Ambiguous signals stay OUT until user confirms.
- **`recommended`**: minimal + `CAP_DAC_READ_SEARCH` (so the app can `ls`/debug like a shell), `CAP_KILL` (cleanly signal children), `CAP_SYS_RESOURCE` (avoid OOM on fork-heavy tools). User must explicitly request this mode.

When the user says "recommended" / "minimal + the convenience set" / "include the comfortable set", use `templates/profile_recommended.json` as the starting skeleton.

## Example invocation (chat)

> User: "I have an APK at /home/z/me/target.apk — generate a KSU profile for it. Use recommended mode."
>
> Assistant:
> 1. Detect target = APK
> 2. Read `pipelines/apk.md`, run `scripts/apk_analyze.py /home/z/me/target.apk`
> 3. For each `lib/<abi>/*.so` in the APK, also run `scripts/binary_analyze.py` on it (per `pipelines/binary.md`)
> 4. Aggregate findings
> 5. Map via `reference/syscall_to_cap.md` (starting from `templates/profile_recommended.json` skeleton)
> 6. Emit 3 JSONs + `analysis.md` + 3 apply scripts under `/home/z/my-project/download/ksu_profile_<pkg>/`
> 7. Print the ambiguous-findings section to chat for the user to answer
> 8. Wait for user reply, then patch JSONs and update `analysis.md`

## What this skill does NOT do

- It does not root devices.
- It does not install KernelSU or any fork.
- It does not call `ksud` to apply the generated profile (user reviews and runs the apply script by hand).
- It does not analyze iOS, embedded RTOS, or non-Android Linux binaries (the capability table is general, but the groups/SELinux rules are Android-specific).
- It does not cover APatch (different root project with its own profile concept — out of scope per user decision).

## After the build

When the workflow completes, briefly summarize in chat: the bundle path, the key capabilities added (and why), the count of ambiguous findings waiting for confirmation, and any unusual signals the user should know about. Suggest next steps: (a) confirm ambiguous findings to refine the profile, (b) apply via the matching `.sh` script after review, (c) re-run with `--from-strace` if the static analysis was inconclusive.
