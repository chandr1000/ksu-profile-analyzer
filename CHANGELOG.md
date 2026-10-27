# Changelog

All notable changes to this skill are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-27

### Fixed — strace pipeline write-family syscall gap

A bug reported by a downstream user (running the skill against the USB-Arsenal
target) revealed that the strace helper was silently dropping all `write()` /
`read()` / `pwrite()` / `pread()` / `writev()` / `readv()` syscall data. The
strace filter `-e trace=%file,%network,%process,%signal,%memory,%ipc` was
missing the `%desc` category, so strace only captured `openat()` calls —
not the subsequent `write()` calls that actually perform the privileged
operation and return EACCES. This caused the skill to miss
`write("/sys/kernel/config/usb_gadget/g1/UDC", "") = -1 EACCES` (which needed
`CAP_DAC_OVERRIDE`) and led the user to chase a downstream `EBUSY` symptom
instead of the upstream root cause.

Audit found 6 related gaps stemming from the same root cause; all are fixed.

- **`templates/strace_capture.sh`**: filter is now
  `-e trace=%file,%desc,%network,%process,%signal,%memory,%ipc` (added `%desc`)
  and the `-y` flag is always passed so strace annotates every fd argument
  with its file path (e.g. `write(3</sys/.../g1/UDC>, "", 0)`). Without
  `-y`, even with the filter fixed, `write(3, "...")` lines would lack the
  path and the parser couldn't map them.
- **`pipelines/strace.md`**: capture recipe updated; strace output example
  now shows the actual `write(3</sys/.../g1/UDC>, "", 0) = -1 EACCES` line
  that was previously invisible; "Limitations" section explains the fix
  and provides an old-strace (<5.3) fallback form.
- **`scripts/strace_analyze.py`** `NOISE_SYSCALLS`: removed
  `read`/`write`/`pread`/`pwrite`/`readv`/`writev` (and a duplicate
  `writev` entry). These syscalls are now handled by a new
  `FD_PATH_HANDLER` special handler.
- **`scripts/strace_analyze.py`** `parse_line()`: new special handler
  (section 0, runs FIRST) detects `write`/`read`/`pwrite`/`pread`/`writev`/
  `readv`/`sendfile`/`splice`/`copy_file_range`/`tee`/`vmsplice` calls,
  extracts the fd→path annotation from `-y`-format
  `write(3</some/path>, ...)` lines, and consults `PATH_MAP` for
  capability mapping.
- **`scripts/strace_analyze.py`** `PATH_MAP`: extended with 8 new entries
  covering the "configfs / sysfs / dev paths typically system:system
  mode 0660" pattern that needs `CAP_DAC_OVERRIDE`:
  `/sys/kernel/config/usb_gadget/`, `/sys/kernel/config/`,
  `/sys/class/`, `/sys/devices/`, `/dev/hidg*`, `/dev/usb/`,
  `/dev/input/`, `/dev/socket/`, `/proc/sys/`, `/sys/module/`.
- **`reference/syscall_to_cap.md`**: new section "File descriptor I/O
  syscalls (write / read / pwrite / pread / writev / readv)" documenting
  (a) why the syscall name alone doesn't imply a cap, (b) the
  "Privileged write targets" table, (c) "Why `openat()` alone is NOT
  enough" with code example, (d) "Downstream symptoms of upstream
  `write()` EACCES failures" explaining the EBUSY-as-downstream-symptom
  pattern.

### Smoke test verified

Synthetic strace trace mimicking the user's exact bug scenario (write to
`/sys/kernel/config/usb_gadget/g1/UDC` returning EACCES, write to
`/sys/kernel/config/usb_gadget/usb_arsenal/UDC` returning EBUSY):

- 6 signals extracted correctly (su_invocation, 2× UDC paths with
  `CAP_DAC_OVERRIDE+CAP_DAC_READ_SEARCH`, /dev/mem with `CAP_SYS_RAWIO`,
  mount with `CAP_SYS_ADMIN`, ptrace with `CAP_SYS_PTRACE`)
- Negative tests passed: regular file `/data/data/com.example/.../cache.txt`
  produced 0 signals (not in PATH_MAP); `write(7, "...")` without `-y`
  annotation produced 0 signals (fd number alone is useless)

## [1.0.0] - 2026-10-27

### Added — initial release

- **3-fork profile emission**: upstream KernelSU, KernelSU-Next, SukiSU-Ultra
  — all three share the same canonical `Profile` data class, so the JSONs
  differ only in `target_fork` and `_meta`.
- **5 analysis pipelines**: APK (apktool + jadx + aapt2), ELF binary
  (readelf + objdump + nm + strings), source repo (ripgrep), runtime strace,
  reference refresh.
- **30-day silent auto-refresh** with changelog footer at the far end of
  every `analysis.md`.
- **Default SELinux context** = `u:r:ksu:s0` (inherited from kernel ksu
  domain); custom per-app SELinux domain is opt-in (Pass 2 interactive
  refinement). Troubleshooting file (`reference/troubleshoot_selinux.md`)
  documents how to debug denials via `dmesg | grep avc` and `audit2allow`.
- **2-pass interactive refinement loop**: Pass 1 emits the best-guess
  minimal profile; Pass 1.5 emits a numbered "⚠️ Ambiguous findings —
  please confirm" section in `analysis.md`; Pass 2 patches the JSONs
  based on user yes/no answers.
- **`currentUid` placeholder + on-device lookup**: emitted as `0` in all
  3 JSONs, with an instruction in `analysis.md` to look it up via
  `adb shell pm list packages -U | grep <pkg>`.
- **Audit-only apply scripts**: 3 shell scripts (one per fork) with a
  `# review-before-run` banner; the skill NEVER auto-executes them.
- **`strace_capture.sh` helper**: ships only when static analysis is
  inconclusive (packed binary, ambiguous syscalls). `analysis.md`
  explains what the file is, why it's needed, and how to use it
  (push to device, run under su, pull logs back, re-invoke with
  `--from-strace <dir>`).
- **Fork detection hint** at the top of every `analysis.md`:
  `adb shell ls /data/adb/` to identify which fork's daemon is installed.
- **Reference data**: 40 Linux capabilities (verbatim from
  `Capabilities.kt`), 120 Android GIDs (verbatim from `Groups.kt`),
  full `Profile` data class (verbatim from `Natives.kt`), and the
  SELinux rules syntax from kernelsu.org/guide/app-profile.html.
- **5 Python orchestration scripts** (stdlib only, no third-party deps).
- **End-to-end smoke-tested** on synthetic repo, ELF, and strace inputs.
