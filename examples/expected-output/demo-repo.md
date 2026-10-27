# Expected output — demo-repo

Running `python3 scripts/repo_analyze.py examples/demo-repo/` should produce
~13 signals (depending on whether the `vendor/` exclusion kicks in for
subdirs that don't exist in this demo):

- 3 AndroidManifest permissions (INTERNET, CHANGE_NETWORK_STATE,
  READ_EXTERNAL_STORAGE)
- C/C++ syscalls (in `native.cpp`): `mount`, `ptrace`, `setuid`
- Java signals (in `MainActivity.java`):
  - `Runtime.exec("su")` → sets allowSu
  - `Shell.su (libsu)` import → sets allowSu
  - `loadLibrary(foo_native)` → recurses into binary pipeline
  - JNI native declaration `nativeMount`
- Hardcoded paths (in `MainActivity.java` and `strings.xml`):
  - `/dev/mem`
  - `/proc/kcore`
  - `/dev/zero` (from `native.cpp` `mount("/dev/zero", ...)` arg)
  - `/system/xbin/su` (from `strings.xml`)

The `mount("/dev/zero", ...)` line in `native.cpp` is interesting — the
repo pipeline's `scan_paths()` regex catches `/dev/zero` as a string and
emits a `file_path` signal. But `/dev/zero` is not in `PATH_MAP`, so the
signal is `confidence: "ambiguous"` with no implied caps. This is correct
behavior — `/dev/zero` is a normal device node accessible to any process,
no special capability needed.

This expected-output file documents the regression baseline.
