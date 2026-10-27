# KernelSU `Profile` data class — canonical schema

This is the verbatim `Profile` data class from `Natives.kt` (upstream KernelSU, `me.weishu.kernelsu` package). **All three KSU-family forks** (upstream KernelSU, KernelSU-Next, SukiSU-Ultra) currently share this exact schema. Only the package path differs:

| Fork | Package |
|---|---|
| KernelSU (upstream) | `me.weishu.kernelsu` |
| KernelSU-Next | `me.weishu.kernelsu` (with optional spoofing) |
| SukiSU-Ultra | `com.sukisu.ultra` |

**Source files** (canonical, current as of last refresh):

- upstream: <https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt>
- KSU-Next: <https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/Natives.kt>
- SukiSU-Ultra: <https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/Natives.kt>

## Constants

```kotlin
const val MINIMAL_SUPPORTED_KERNEL = 32513
const val KERNEL_SU_DOMAIN = "u:r:ksu:s0"
const val ROOT_UID = 0
const val ROOT_GID = 0
const val FLAG_KSU_NO_NEW_PRIVS = 1L
private const val NON_ROOT_DEFAULT_PROFILE_KEY = "$"
private const val NOBODY_UID = 9999
```

## `Profile` data class

```kotlin
@Keep
@Immutable
@Parcelize
@Serializable
data class Profile(
    // and there is a default profile for root and non-root
    val name: String,
    // current uid for the package, this is convenient for kernel to check
    // if the package name doesn't match uid, then it should be invalidated.
    val currentUid: Int = 0,
    // if this is true, kernel will grant root permission to this package
    val allowSu: Boolean = false,
    // these are used for root profile
    val rootUseDefault: Boolean = true,
    val rootTemplate: String? = null,
    val uid: Int = ROOT_UID,
    val gid: Int = ROOT_GID,
    val groups: List<Int> = mutableListOf(),
    val capabilities: List<String> = mutableListOf(),
    val context: String = KERNEL_SU_DOMAIN,
    val namespace: Int = Namespace.INHERITED.ordinal,
    val nonRootUseDefault: Boolean = true,
    val umountModules: Boolean = true,
    var rules: String = "", // this field is save in ksud!!
    val flags: Long = FLAG_KSU_NO_NEW_PRIVS,
) : Parcelable {
    @Keep
    enum class RootProfileFlag(val display: String, val desc: Int) {
        NO_NEW_PRIVS(
            "NO_NEW_PRIVS",
            R.string.profile_flags_desc_no_new_privs
        )
    }
    enum class Namespace {
        INHERITED,
        GLOBAL,
        INDIVIDUAL,
    }
    constructor() : this("")
}
```

## Field-by-field reference

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | `String` | (required) | Package name (e.g. `com.example.foo`). For the non-root default profile, use the special key `"$"`. |
| `currentUid` | `Int` | `0` | The actual installed UID of the package on the device (`10000`–`19999` for normal apps). The kernel verifies that `name` ↔ `currentUid` matches; mismatches invalidate the profile. Static analysis cannot know this — emit `0` and instruct the user to look it up. |
| `allowSu` | `Boolean` | `false` | If `true`, the kernel grants `su` to this package. Set to `true` only when the user explicitly asked for a root profile. |
| `rootUseDefault` | `Boolean` | `true` | If `true`, ignore the rest of the root profile fields and use the kernel's default root profile. Set to `false` when emitting a custom root profile. |
| `rootTemplate` | `String?` | `null` | Name of a saved root profile template to load. Only set when the user references a specific saved template. |
| `uid` | `Int` | `0` (ROOT_UID) | UID the `su` process will run as. `0` = full root; `2000` = ADB shell level; other values fine-tune. |
| `gid` | `Int` | `0` (ROOT_GID) | Primary GID for the `su` process. |
| `groups` | `List<Int>` | `[]` | Supplementary GIDs. See `reference/groups.md` for the full Android GID table. |
| `capabilities` | `List<String>` | `[]` | Linux capabilities to grant (e.g. `"CAP_NET_RAW"`). See `reference/capabilities.md`. |
| `context` | `String` | `"u:r:ksu:s0"` | SELinux context for the `su` process. Default = inherited from the kernel's ksu domain. Custom domains are optional and require a `rules` block. |
| `namespace` | `Int` | `0` (INHERITED) | Mount namespace mode. `0` = INHERITED (inherit the caller's), `1` = GLOBAL (kernel's global), `2` = INDIVIDUAL (isolated per-app). |
| `nonRootUseDefault` | `Boolean` | `true` | If `true`, use the kernel's default non-root profile for this app. Set to `false` when emitting custom non-root behavior. |
| `umountModules` | `Boolean` | `true` | If `true`, KernelSU will umount any mounted modules from this app's view — used to hide KSU from the app (e.g. for banking apps). |
| `rules` | `String` | `""` | SELinux policy rules to inject (multi-line, kernel SELinux CIL-like syntax). Stored in `ksud`, not in the kernel struct. Empty by default. |
| `flags` | `Long` | `1L` (FLAG_KSU_NO_NEW_PRIVS) | Bitmask. Bit 0 = NO_NEW_PRIVS (always set for hardening). |

## Enums

### `RootProfileFlag`

| Ordinal | Name | Meaning |
|---|---|---|
| 0 | `NO_NEW_PRIVS` | Set `PR_SET_NO_NEW_PRIVS` on the su'd process — prevents gaining new privileges via execve of setuid binaries. Always set. |

### `Namespace`

| Ordinal | Name | Meaning |
|---|---|---|
| 0 | `INHERITED` | Inherit the calling app's mount namespace (default — most apps want this). |
| 1 | `GLOBAL` | Use the kernel's global/init mount namespace (more powerful, more visible). |
| 2 | `INDIVIDUAL` | Isolated per-app mount namespace (most confined). |

## External functions (relevant ones)

```kotlin
external fun getAppProfile(key: String?, uid: Int): Profile
external fun setAppProfile(profile: Profile?): Boolean
external fun uidShouldUmount(uid: Int): Boolean
external fun isSuEnabled(): Boolean
external fun setSuEnabled(enabled: Boolean): Boolean
external fun isKernelUmountEnabled(): Boolean
external fun setKernelUmountEnabled(enabled: Boolean): Boolean
external fun isSelinuxHideEnabled(): Boolean
external fun setSelinuxHideEnabled(enabled: Boolean): Int
external fun getUserName(uid: Int): String?
external fun getSuperuserCount(): Int
```

The `setAppProfile` function is what `ksud profile set` calls under the hood — it serializes the `Profile` and sends it to the kernel via the supercall interface.

## SukiSU-Ultra extras (manager-level, not in `Profile`)

SukiSU-Ultra adds these top-level `Natives` functions, but they are **manager toggles** (not part of the Profile data class):

```kotlin
external fun getFullVersion(): String?      // returns e.g. "v4.0.0"
external fun isAvcSpoofEnabled(): Boolean   // AVC audit log SID spoofing (SUSFS)
external fun setAvcSpoofEnabled(enabled: Boolean): Boolean
external fun isMountHideEnabled(): Boolean  // mount hide (SUSFS)
external fun setMountHideEnabled(enabled: Boolean): Int
external fun getHookType(): String
```

These affect the whole system, not a specific app profile. The skill does NOT emit these in the profile JSON — they are user-controlled via the SukiSU-Ultra manager UI.

## KernelSU-Next extras (manager-level)

KernelSU-Next adds backup/restore for app profiles at the manager level — a UI feature, not a profile schema extension. The `Profile` data class itself is identical to upstream.

## History of kernel UAPI version markers

From the comments at the top of `Natives.kt`:

```
// 10915: allowlist breaking change, add app profile
// 10931: app profile struct add 'version' field
// 10946: add capabilities
// 10977: change groups_count and groups to avoid overflow write
// 11071: Fix the issue of failing to set a custom SELinux type.
// 12143: breaking: new supercall impl
// 32310: new get_allow_list ioctl
// 32336: new set_sepolicy ioctl
// 32377: add set_init_pgrp ioctl
// 32513: add uapi version  (MINIMAL_SUPPORTED_KERNEL)
```

If the user's kernel reports a version < 32513 via `cat /proc/version` or the KSU manager's "Kernel version" field, the App Profile feature is unavailable — tell them and abort the workflow.
