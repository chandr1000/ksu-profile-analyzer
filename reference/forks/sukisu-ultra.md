# Fork: SukiSU-Ultra

A maintained fork focused on broader kernel coverage (4.x → 5.4 with LTS mode, 3.x experimental), KPM (Kernel Patch Module) integration ported from APatch, SUSFS at the manager level, and deeper manager customization.

## Repository

- **Repo**: <https://github.com/SukiSU-Ultra/SukiSU-Ultra>
- **Default branch**: `main`
- **Manager package**: `com.sukisu.ultra` (different from upstream!)
- **Daemon binary**: `ksud` (same binary name as upstream — fork does not rename)
- **Kernel module**: `kernelsu.ko` (or built-in) + optional `kpm.ko` for KPM
- **Website**: <https://sukisu.org>

## Profile schema deltas vs upstream

**None at the Profile data class level.** SukiSU-Ultra ships the same `Profile` data class with the same fields, defaults, and enums. The 40 `CAP_*` capabilities and Android GID table are byte-identical.

Source of truth:

```
https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/Natives.kt
https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Capabilities.kt
https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Groups.kt
```

## Manager-level extras (top-level Natives functions)

SukiSU-Ultra adds these top-level `Natives` functions for SUSFS / KPM features. **These are manager-level toggles, not Profile fields.** The skill does NOT emit them in the profile JSON.

```kotlin
external fun getFullVersion(): String?                // returns "v4.0.0" or similar
external fun isAvcSpoofEnabled(): Boolean             // AVC audit log SID spoofing (SUSFS)
external fun setAvcSpoofEnabled(enabled: Boolean): Boolean
external fun isMountHideEnabled(): Boolean            // mount hide (SUSFS)
external fun setMountHideEnabled(enabled: Boolean): Int
external fun getHookType(): String                    // kernel hook type (kprobes, etc.)
```

Plus these from upstream (inherited as-is):

```kotlin
external fun isSuEnabled(): Boolean
external fun setSuEnabled(enabled: Boolean): Boolean
external fun isKernelUmountEnabled(): Boolean
external fun setKernelUmountEnabled(enabled: Boolean): Boolean
external fun isSelinuxHideEnabled(): Boolean
external fun setSelinuxHideEnabled(enabled: Boolean): Int
```

## Manager-level extras (UI features, not Profile fields)

| Feature | Where it lives | Affects profile? |
|---|---|---|
| SUSFS mount hide | Manager toggle (`isMountHideEnabled`) + kernel `susfs` module | No — system-level toggle |
| SUSFS AVC audit spoof | Manager toggle (`isAvcSpoofEnabled`) | No — system-level toggle |
| KPM (Kernel Patch Module) loading | `kpm` userspace + kernel CONFIG_KPM=y | No — separate module system |
| Spoofed package ID | Build-time script | No — manager APK identity |
| LTS mode for non-GKI kernels | Build-time flag | No — kernel feature |

## Daemon invocation

Same as upstream — `ksud` is the binary name:

```sh
ksud profile set /path/to/profile.json
ksud profile get <package_name> <uid>
ksud profile list
```

(Confirmed by `build-ksud.yml` GitHub Actions workflow in the SukiSU-Ultra repo.)

## Detection on device

```sh
# Check which fork is installed:
adb shell ls /data/adb/ | grep -E 'ksu|ksnd|sukid'
# SukiSU-Ultra uses the same `ksud` binary name.
# Distinguish by the manager package:
adb shell pm list packages | grep -E 'sukisu|com.sukisu.ultra'
# Or:
adb shell dumpsys package com.sukisu.ultra | grep versionName
```

## Why the schema didn't diverge

SukiSU-Ultra forks the upstream `Natives.kt` directly and adds SUSFS / KPM as separate concerns (kernel module + userspace toggles). The App Profile concept remains upstream-compatible — this lets users switch between forks without re-applying profiles.

## When to recommend SukiSU-Ultra

- The user's device kernel is < 5.10 (non-GKI, especially 4.x series).
- The user wants KPM (Kernel Patch Module) support.
- The user wants SUSFS (anti-detection: mount hide + AVC spoof).
- The user wants LTS mode for older kernels.

## KSU_MINIMAL_SUPPORTED_KERNEL_FULL

SukiSU-Ultra adds this constant:

```kotlin
const val MINIMAL_SUPPORTED_KERNEL_FULL = "v4.0.0"
```

This is used by `isFullFeatured()` to also accept kernel versions >= v4.0.0 (string comparison), as a fallback for forks that don't report the numeric `MINIMAL_SUPPORTED_KERNEL` correctly. The skill does not need to special-case this — if the user's kernel reports a lower version, the App Profile feature is unavailable regardless of fork.
