# Fork: KernelSU (upstream) — canonical base

This is the **canonical** Profile schema. Both forks (KSU-Next, SukiSU-Ultra) extend this only at the **manager level** — the Profile data class itself is identical across all three.

## Repository

- **Upstream repo**: <https://github.com/tiann/KernelSU>
- **Default branch**: `main`
- **Manager package**: `me.weishu.kernelsu`
- **Daemon binary**: `ksud` (Rust userspace, lives in `/data/adb/ksud`)
- **Kernel module**: `kernelsu.ko` (or built-in to the kernel)

## Source files of interest

| File | Purpose |
|---|---|
| `manager/app/src/main/java/me/weishu/kernelsu/Natives.kt` | JNI bindings + `Profile` data class + constants |
| `manager/app/src/main/java/me/weishu/kernelsu/profile/Capabilities.kt` | The 40-entry `CAP_*` enum |
| `manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt` | All Android GIDs |
| `userspace/ksud/src/profile.rs` | `ksud profile set` implementation |
| `kernel/include/linux/kernelsu.h` | Kernel-side profile struct (mirror of `Natives.kt`) |

## Key constants

```kotlin
const val MINIMAL_SUPPORTED_KERNEL = 32513   // uapi version 1
const val KERNEL_SU_DOMAIN = "u:r:ksu:s0"
const val ROOT_UID = 0
const val ROOT_GID = 0
const val FLAG_KSU_NO_NEW_PRIVS = 1L
private const val NON_ROOT_DEFAULT_PROFILE_KEY = "$"
private const val NOBODY_UID = 9999
```

## Profile schema (canonical)

See `reference/ksu_profile_schema.md` for the verbatim data class.

## Daemon invocation

The `ksud` daemon supports (verified from `userspace/ksud/src/profile.rs`):

```sh
# Set a profile from a JSON file:
ksud profile set /path/to/profile.json

# Get the current profile for a package:
ksud profile get <package_name> <uid>

# List all root profiles:
ksud profile list
```

The JSON format mirrors the Kotlin `Profile` data class exactly (field names are the same — snake_case is NOT used).

## Manager-level toggles

The upstream KernelSU manager exposes these global toggles (not per-app):

| Toggle | JNI function | Meaning |
|---|---|---|
| `su` compat mode | `isSuEnabled()` / `setSuEnabled(enabled)` | Globally allow/disallow `su` invocations |
| Kernel module umount | `isKernelUmountEnabled()` / `setKernelUmountEnabled(enabled)` | Globally allow/disallow KSU module umount |
| SELinux hide | `isSelinuxHideEnabled()` / `setSelinuxHideEnabled(enabled)` | Hide SELinux state (`getenforce` returns "Disabled" when actually Enforcing) — anti-detection |

These are NOT in the Profile JSON. The skill does not emit them.

## Minimum supported kernel

`MINIMAL_SUPPORTED_KERNEL = 32513`. If the user's kernel reports a lower version, App Profile is unavailable. Check:

```sh
adb shell su -c 'cat /sys/module/kernelsu/version'
# Or via manager UI: "Kernel version" field
```

The kernel UAPI version is also exposed via `kernelUAPIVersion` in `Natives.kt`.
