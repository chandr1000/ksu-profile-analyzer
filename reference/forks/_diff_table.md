# Fork diff matrix

Quick side-by-side comparison of the three KSU-family forks.

## Profile schema (the JSON the skill emits)

| Aspect | KernelSU (upstream) | KernelSU-Next | SukiSU-Ultra |
|---|---|---|---|
| `Profile` data class fields | 16 (canonical) | identical | identical |
| `Capabilities` table | 40 entries | identical | identical |
| `Groups` table | 120 entries | identical | identical |
| `Namespace` enum | INHERITED, GLOBAL, INDIVIDUAL | identical | identical |
| `RootProfileFlag` enum | NO_NEW_PRIVS | identical | identical |
| `KERNEL_SU_DOMAIN` | `u:r:ksu:s0` | identical | identical |
| `FLAG_KSU_NO_NEW_PRIVS` | `1L` | identical | identical |
| `MINIMAL_SUPPORTED_KERNEL` | `32513` | identical | identical |
| Manager package | `me.weishu.kernelsu` | `me.weishu.kernelsu` (or spoofed `com.rifsxd.ksunext`) | `com.sukisu.ultra` |
| Daemon binary | `ksud` | `ksud` | `ksud` |
| `ksud profile set` command | yes | yes | yes |
| `ksud profile get` command | yes | yes | yes |
| `ksud profile list` command | yes | yes | yes |

**Conclusion**: the skill emits **3 byte-identical JSONs** (differing only in `target_fork` and `_meta`), because the schemas are identical. The 3 apply scripts also call the same command — they differ only in the JSON path they point at and the explanatory banner.

## Manager-level extras (NOT in Profile, NOT emitted by skill)

| Feature | KernelSU | KSU-Next | SukiSU-Ultra |
|---|---|---|---|
| `su` compat mode toggle (`isSuEnabled`) | yes | yes | yes |
| Kernel module umount toggle (`isKernelUmountEnabled`) | yes | yes | yes |
| SELinux hide toggle (`isSelinuxHideEnabled`) | yes | yes | yes |
| App profile backup/restore (UI) | no | yes | (varies by version) |
| SUSFS LKM auto-load | no | yes | yes (built-in) |
| SUSFS mount hide toggle | no | no | yes (`isMountHideEnabled`) |
| SUSFS AVC audit spoof toggle | no | no | yes (`isAvcSpoofEnabled`) |
| KPM (Kernel Patch Module) | no | no | yes |
| Risk detection (blocks malicious modules) | no | yes | (varies) |
| Spoofed package ID | no | yes (via `spoof` script) | (varies) |
| Metamodules | no | yes | (varies) |
| LTS mode for non-GKI | no | partial | yes (4.x → 5.4) |

## Kernel coverage

| Fork | Min kernel | Max kernel |
|---|---|---|
| KernelSU (upstream) | 5.10 (GKI 2.0) | latest |
| KernelSU-Next | 4.4 | 6.18 |
| SukiSU-Ultra | 3.x (experimental) | latest |

## Detection cheat sheet (top of every analysis.md)

```sh
adb shell ls /data/adb/ | grep -E 'ksu|ksnd|sukid'
# All three forks currently use `ksud` as the binary name.
# Distinguish by manager package:

# KernelSU (upstream):
adb shell pm list packages me.weishu.kernelsu

# KernelSU-Next (or spoofed):
adb shell pm list packages | grep -E 'kernelsu|rifsxd'

# SukiSU-Ultra:
adb shell pm list packages | grep -E 'sukisu|com.sukisu.ultra'
```

## Apply script behavior

All 3 apply scripts:

1. Take the matching `profile.<fork>.json` as input
2. Run `ksud profile set <path>` (the command is identical across forks)
3. Print a `# review-before-run` banner instructing the user to read the JSON first

The scripts differ only in:
- The banner text (mentions the specific fork)
- The JSON path they reference
- The post-apply verification commands (e.g. `dumpsys package <fork_pkg>` to confirm)

## When the schemas diverge in the future

If a future version of one of the forks adds a Profile field (e.g. SukiSU-Ultra adds a `kpm_allow` field), the skill should:

1. Update `reference/forks/<fork>.md` with the new field
2. Update `reference/ksu_profile_schema.md` with the new field (marked as fork-specific)
3. Update `templates/profile_minimal.json` and `profile_recommended.json` to include the new field under a `fork_extensions` block (only populated when `target_fork` matches)
4. Re-run `scripts/refresh_references.py` to verify the field is still there

The `fork_extensions` block in the JSON is reserved for this future use:

```json
{
  "target_fork": "sukisu-ultra",
  "schema_version": "2026-10-28",
  "profile": { /* canonical fields */ },
  "fork_extensions": {
    "sukisu-ultra": {
      "_note": "Currently no fork-specific profile fields. SUSFS / KPM are manager-level toggles, not profile fields."
    }
  }
}
```

Today the block is informational only.
