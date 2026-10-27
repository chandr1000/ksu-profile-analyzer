# Fork: KernelSU-Next

A maintained fork of upstream KernelSU. Adds SUSFS (loadable kernel module driver for systemless file-system spoofing), wider kernel coverage (4.4 → 6.18), risk detection for malicious modules, and **backup/restore for app profiles**.

## Repository

- **Repo**: <https://github.com/KernelSU-Next/KernelSU-Next>
- **Default branch**: `main`
- **Manager package**: `me.weishu.kernelsu` (with optional spoofing via the `spoof` script — randomizes package name `com.rifsxd.ksunext` to evade detection)
- **Daemon binary**: `ksud` (same binary name as upstream — fork does not rename)
- **Kernel module**: `kernelsu.ko` (or built-in)
- **Website**: <https://kernelsu-next.github.io/webpage/>

## Profile schema deltas vs upstream

**None.** KernelSU-Next's `Profile` data class is byte-identical to upstream KernelSU. The same 40 `CAP_*` capabilities, the same Android GIDs, the same `context`/`rules`/`namespace`/`flags` semantics.

Source of truth:

```
https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt
https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt
https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt
```

## Manager-level extras

| Feature | Where it lives | Affects profile? |
|---|---|---|
| App profile backup/restore | Manager UI (export/import .json or .zip) | No — same schema, just file I/O |
| Metamodules (pluggable module infrastructure) | Kernel + userspace | No — module system, not profile |
| SUSFS LKM auto-load on boot | Kernel + `susfsd` daemon | No — system-level toggle |
| Risk detection (blocks suspicious modules at install time) | Manager UI + kernel hooks | No — install-time gate |
| Spoofed package name | Build-time `spoof` script | No — manager APK identity, not profile |

## Daemon invocation

Same as upstream — `ksud` is the binary name:

```sh
ksud profile set /path/to/profile.json
ksud profile get <package_name> <uid>
ksud profile list
```

(Confirmed by the GitHub Actions workflow `build-ksud.yml` in the repo that produces the `ksud` binary for all platforms.)

## Detection on device

```sh
# Check which fork is installed:
adb shell ls /data/adb/ | grep -E 'ksu|ksnd|sukid'
# KernelSU-Next uses the same `ksud` binary name as upstream.
# Distinguish from upstream by checking the manager version:
adb shell dumpsys package me.weishu.kernelsu | grep versionName
# OR the spoofed variant:
adb shell dumpsys package com.rifsxd.ksunext | grep versionName
```

If the user is unsure, the skill should default to the upstream `profile.kernelsu.json` (since the schema is identical anyway) and emit `apply.ksu-next.sh` for completeness — the apply command is the same.

## Why the schema didn't diverge

KernelSU-Next maintains near-1:1 compatibility with upstream's kernel module + uapi to allow users to switch between the two without reinstalling. The fork's value-adds are at the **userspace and module layer**, not at the kernel-profile layer.

## When to recommend KernelSU-Next

- The user's device kernel is < 5.10 (non-GKI) and upstream KernelSU doesn't support it.
- The user wants SUSFS LKM auto-load.
- The user wants app-profile backup/restore.
- The user wants spoofed package ID (evades root-detection apps).
