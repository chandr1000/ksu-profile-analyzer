# Troubleshooting SELinux denials (custom domain mode)

If you opted into a custom SELinux domain (`context = "u:r:app_<pkg>:s0"`) and the app starts failing silently, this file is your debugging checklist. SELinux denials rarely crash apps — they usually manifest as a syscall returning `EACCES` (Permission denied), which the app may not handle gracefully.

## Step 1 — Confirm it's actually a SELinux problem

Switch the system to permissive temporarily. **This is for diagnosis only — revert before going back to production.**

```sh
# On device (must be root via su):
adb shell su -c 'setenforce 0'

# Now try the failing operation again.
# If it works in permissive but not enforcing, it's a SELinux denial.

# Revert:
adb shell su -c 'setenforce 1'
```

If the operation still fails in permissive mode, the problem is **not** SELinux — look elsewhere (capabilities, groups, file permissions, missing files).

## Step 2 — Find the actual denial

```sh
# dmesg is the canonical source:
adb shell su -c 'dmesg | grep avc | tail -50'

# Or logcat (Android's view):
adb shell su -c 'logcat -b all -d | grep avc | tail -50'

# For real-time monitoring:
adb shell su -c 'logcat -b all | grep avc'
```

A typical denial line looks like:

```
[12345.678] audit: type=1400 audit(1700000000.123:456): avc:  denied  { read write } for  pid=1234 comm="myapp" name="foo" dev="tmpfs" ino=4567 scontext=u:r:app_my_pkg:s0 tcontext=u:object_r:foo_device:s0 tclass=chr_file permissive=0
```

Decode the fields:

| Field | Meaning |
|---|---|
| `denied { read write }` | The permissions that were denied. |
| `pid=`, `comm=` | The offending process. |
| `scontext=u:r:app_my_pkg:s0` | The source (your custom domain). |
| `tcontext=u:object_r:foo_device:s0` | The target type (the resource). |
| `tclass=chr_file` | The object class (chr_file = character device file). |
| `permissive=0` | 0 = enforcing (blocked), 1 = permissive (logged but allowed). |

## Step 3 — Generate the `allow` rule

Two options:

### Option A — Hand-write the rule

Translate the denial into a rule:

```
allow app_my_pkg foo_device chr_file { read write }
```

Append this to your `rules` field in the profile JSON, then re-apply:

```sh
ksud profile set /path/to/profile.json
```

### Option B — Use `audit2allow`

If your device has `audit2allow` (most non-Android Linux has it; Android usually doesn't, but it can be run from your PC):

```sh
# Pull dmesg to PC:
adb shell su -c 'dmesg | grep avc' > avc_denials.log

# Generate allow rules:
audit2allow -i avc_denials.log
```

This prints a list of `allow` rules you can paste into `rules`.

## Step 4 — Test with permissive-on-this-type

If you want to confirm your rule fixes the issue without weakening the whole system:

```
# In rules, add this temporary line:
permissive app_my_pkg

# Re-apply, run the failing op — should succeed.
# Then remove the permissive line and re-apply.
```

## Step 5 — Common denial patterns

| Denial | Likely cause | Fix |
|---|---|---|
| `denied { search }` on `/data/...` | App needs DAC read on a path it doesn't own | Add `CAP_DAC_READ_SEARCH` to capabilities, OR add `allow app_<pkg> app_data_file dir search` |
| `denied { read write }` on `/dev/<X>` | App needs a device node | Add `allow app_<pkg> <X>_device chr_file { read write }` (find the right `<X>_device` type) |
| `denied { execute }` on `/system/bin/su` | App tries to call `su` | Already covered — `allowSu=true` should grant this; if not, check `rules` for explicit deny |
| `denied { mount }` on a filesystem | App calls `mount()` | `CAP_SYS_ADMIN` is required AND the SELinux allow rule: `allow app_<pkg> <fs_type> filesystem mount` |
| `denied { read }` on `/proc/<pid>/maps` | App tries to read another process's memory | `CAP_SYS_PTRACE` + `allow app_<pkg> proc_pid_file file read` |
| `denied { setuid }` | App tries to drop privileges | `CAP_SETUID` + `allow app_<pkg> self capability setuid` |
| `denied { create }` on `socket(AF_INET, SOCK_RAW)` | Raw socket | `CAP_NET_RAW` + group `3004` + `allow app_<pkg> self rawip_socket create` |

## Step 6 — If you can't figure it out

### Revert to inherited context (safe default)

Edit the profile JSON:

```json
{
  "context": "u:r:ksu:s0",
  "rules": ""
}
```

Re-apply: `ksud profile set /path/to/profile.json`. This gives up the custom domain and falls back to the kernel's ksu domain, which is far more permissive. Use this only as a last resort — it loses the per-app isolation benefit.

### Capture full audit

For deep debugging, enable full audit logging:

```sh
# On device, with su:
auditctl -w /path/to/file -p rwxa    # watch a specific path
auditctl -l                          # list current watches
auditctl -D                          # delete all watches
```

(Android kernels often have audit disabled — if `auditctl` returns "operation not supported", fall back to `dmesg | grep avc`.)

### Check kernel SELinux booleans

```sh
adb shell su -c 'getsebool -a'
```

Some booleans like `allow_ptrace` or `global_bl` (bypassmls) may need flipping for specific operations.

## Sources

- KernelSU App Profile docs: <https://kernelsu.org/guide/app-profile.html>
- Android SELinux docs: <https://source.android.com/security/selinux>
- `audit2allow` man page: <https://man7.org/linux/man-pages/man8/audit2allow.8.html>
- `setenforce` / `getenforce`: <https://man7.org/linux/man-pages/man8/setenforce.8.html>

## When to give up

If you've spent >30 minutes on SELinux denials and the app still doesn't work, switch to the inherited `u:r:ksu:s0` context. The confinement benefit isn't worth the debugging time. Use the rest of the Profile (capabilities + groups) for the privilege boundary — it covers most of the attack surface anyway.
