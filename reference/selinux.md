# SELinux context & rules for KernelSU App Profiles

KernelSU's root profile can run the `su` process in a custom SELinux domain. The default is `u:r:ksu:s0` (inherited from the kernel's ksu domain). For most apps, the inherited context is fine — **do not auto-emit a custom domain**.

## When to use a custom domain

Only suggest a custom domain in `analysis.md` as an opt-in. Use cases:

- The app needs stricter SELinux isolation (e.g. a sensitive root app that should be confined further).
- The app needs additional SELinux permissions beyond what `u:r:ksu:s0` allows.
- The user wants per-app SELinux audit logging.

For most apps, the inherited context with `rules: ""` is sufficient. **If the user does not explicitly opt in, leave `context = "u:r:ksu:s0"` and `rules = ""`.**

## Rules syntax

The `rules` field is a multi-line string of SELinux policy statements. KernelSU uses the same CIL-like syntax as Android's SELinux policy. Example from the official docs:

```
type app1
enforce app1
typeattribute app1 mlstrustedsubject
allow app1 * * *
```

Each statement:

| Statement | Meaning |
|---|---|
| `type <name>` | Declare a new SELinux type (the domain). |
| `enforce <name>` | Mark the type as enforcing (denials are logged AND enforced). Without this, the type is permissive (denials logged but not enforced) — useful for debugging. |
| `typeattribute <name> <attr>` | Add the type to an attribute group. `mlstrustedsubject` allows the type to bypass MLS (Multi-Level Security) constraints. |
| `allow <scontext> <tcontext> <class> <perms>` | Allow `scontext` to perform `perms` on `class` of `tcontext`. Use `*` for wildcards. |
| `deny <s> <t> <c> <p>` | Explicitly deny a permission (rare). |
| `auditallow <s> <t> <c> <p>` | Log when this permission is granted (for audit). |
| `dontaudit <s> <t> <c> <p>` | Suppress denial logs for this rule (use sparingly — hides real issues). |

## Skill-generated template (when user opts in)

When the user explicitly asks for a custom SELinux domain in Pass 2, generate:

```
type app_<sanitized_pkg>
enforce app_<sanitized_pkg>
typeattribute app_<sanitized_pkg> mlstrustedsubject
allow app_<sanitized_pkg> * * *
```

And set:

```json
{
  "context": "u:r:app_<sanitized_pkg>:s0",
  "rules": "type app_<sanitized_pkg>\nenforce app_<sanitized_pkg>\ntypeattribute app_<sanitized_pkg> mlstrustedsubject\nallow app_<sanitized_pkg> * * *"
}
```

Where `<sanitized_pkg>` is the package name with `.` replaced by `_` (e.g. `com.example.foo` → `com_example_foo`).

## Default (no custom domain)

For the 95% case:

```json
{
  "context": "u:r:ksu:s0",
  "rules": ""
}
```

This means the `su` process inherits the kernel's ksu domain — same as a vanilla `su` invocation. No `rules` block is injected.

## Sources

- Official docs: <https://kernelsu.org/guide/app-profile.html>
- The `rules` field is stored in `ksud` (the userspace daemon), not in the kernel struct directly. The kernel calls `set_sepolicy` ioctl to apply them.
- The "enforce" statement is critical — without it, the type is permissive (denials logged but not blocked), which is useful for first-pass debugging but should be flipped to enforcing before production use.

## When NOT to emit custom rules

- Don't emit custom rules for apps that should not get root (`allowSu: false`) — those apps don't run `su`, so the context/rules don't apply.
- Don't emit `allow` rules for resources the app doesn't access — start permissive and let `dmesg | grep avc` reveal the actual denials (see `troubleshoot_selinux.md`).
- Don't emit `dontaudit` rules without strong justification — they hide real problems.

## How `ksud` applies the rules

When the user runs the apply script:

```sh
ksud profile set /path/to/profile.json
```

`ksud` parses the `rules` string, calls the kernel's `set_sepolicy` supercall to inject each rule, and then sets the rest of the profile (uid/gid/groups/capabilities/context/namespace/flags). The rules persist across reboots because `ksud` re-applies them on each boot.

## Verifying applied rules

After applying, the user can check:

```sh
# What domain does my su process get?
adb shell su -c 'id -Z'
# Expected: u:r:ksu:s0 (default) or u:r:app_<pkg>:s0 (custom)

# Recent SELinux denials
adb shell dmesg | grep avc | tail -50

# Full SELinux status
adb shell getenforce       # Enforcing or Permissive
adb shell selinux_enabled  # 1
```
