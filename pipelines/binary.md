# Pipeline: ELF binary analysis

Extract signals from a native ELF binary (`.so`, executable, etc.). This pipeline is used directly when the user gives a binary target, AND recursively by `pipelines/apk.md` for each `lib/<abi>/*.so` inside an APK.

## Inputs

- `target`: absolute path to the ELF file
- `parent_source` (optional): tag for `findings.json` source attribution (e.g. `apk:lib/arm64-v8a/libfoo.so`)

## Tools

| Tool | Used for |
|---|---|
| `file` | Identify ELF arch/class |
| `readelf -aW` | ELF header, dynamic section, symbols, sections |
| `objdump -T` | Dynamic symbol table (imports) |
| `objdump -t` | Symbol table (for non-stripped binaries) |
| `nm -D --defined-only` | Defined dynamic symbols (exports) |
| `nm -D --undefined-only` | Undefined dynamic symbols (imports) — what we care about |
| `strings -a -n 4` | Hardcoded strings (file paths, dev nodes, su paths) |
| `ldd` (if host-arch matches) | Direct shared-lib dependencies |

For ARM/ARM64 binaries on an x86 host, you cannot run `ldd`. Use `readelf -d` instead — the `NEEDED` entries list dependencies.

## Workflow

### 1. Identify the binary

```sh
file /path/to/target.so
# Output: ELF 64-bit LSB shared object, ARM aarch64, ...
```

Record arch (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`, `riscv64`) and class (shared lib vs executable).

### 2. Pull dynamic symbol imports (the canonical signal source)

```sh
# All undefined (imported) dynamic symbols — what the binary expects from libc etc.:
nm -D --undefined-only /path/to/target.so > imports.txt

# Or via readelf (more verbose, includes version info):
readelf -W --dyn-syms /path/to/target.so | grep 'UND' >> imports.txt
```

Parse each imported symbol name and look it up in the "Imported libc symbols" section of `reference/syscall_to_cap.md`. Each match becomes a `syscall` signal in `findings.json` with `source: "binary:<basename>"` (or `parent_source` if provided).

### 3. Pull hardcoded strings

```sh
strings -a -n 4 /path/to/target.so > strings.txt
# Filter for interesting paths/devices:
grep -E '^/(dev|proc|sys|data|system|sbin)' strings.txt > paths.txt
grep -E '(su|magisk|kernelsu)' strings.txt > su_strings.txt
```

Each path entry becomes a `file_path` signal. Look it up in the "Device nodes (file path signals)" section of `reference/syscall_to_cap.md`. `su_strings.txt` entries that look like su paths (e.g. `/system/xbin/su`) become `su_invocation` signals with `confidence: ambiguous` (presence of the string isn't proof of use).

### 4. Disassemble hot paths (optional, for ambiguous signals)

If the binary imports `mount` but you want to verify it's actually called (not just transitively linked), do a quick disassembly check:

```sh
objdump -d /path/to/target.so | grep -E 'call.*mount$'
# Or for ARM:
objdump -d /path/to/target.so | grep -E 'bl.*<mount'
```

If the call site exists, bump the signal's confidence from `ambiguous` to `unambiguous`. If not, leave as ambiguous — the binary may still call it via dlopen/dlsym or via another lib.

### 5. Inspect NEEDED libraries (for chaining)

```sh
readelf -d /path/to/target.so | grep NEEDED
# Output: NEEDED liblog.so, NEEDED libc.so, NEEDED libm.so, ...
```

If the binary `NEEDED`s an unusual library (e.g. `libcap.so`, `libselinux.so`, `libaudit.so`, `libbpf.so`), record it as an additional signal — these strongly suggest the binary uses the corresponding capability (`CAP_SETFCAP`, SELinux ops, `CAP_AUDIT_*`, `CAP_BPF`).

### 6. Check for stripped binaries

```sh
readelf -h /path/to/target.so | grep -E 'Type|Machine'
nm /path/to/target.so 2>&1 | head -3
# If 'no symbols' — binary is stripped; rely on dynamic imports + strings only
```

Stripped binaries have NO `.symtab` (full symbol table) but usually still have `.dynsym` (dynamic symbol table needed at runtime). The dynamic imports are still recoverable — Step 2 above still works.

If both are missing (extremely rare, suggests deliberate obfuscation), emit a `stripped_binary` signal — this triggers the `strace_capture.sh` recommendation in `analysis.md`.

### 7. Check for packed/encrypted binaries

```sh
strings -a /path/to/target.so | head -50
# If output looks random/encrypted (no readable strings), flag as packed
```

Packed binaries (UPX, custom packers) have no readable strings. The unpacking happens at runtime — defer to strace.

### 8. Identify JNI entry points (for .so inside APKs)

```sh
readelf -W --dyn-syms /path/to/target.so | grep 'Java_'
# Output: Java_com_example_Foo_nativeMount, Java_com_example_Foo_nativeSetuid, ...
```

JNI entry point names follow `Java_<package>_<Class>_<method>` — they explicitly tell you what the Java side will call. A `Java_com_example_Foo_nativeMount` entry means the Java side calls `Foo.nativeMount()` — strong signal for `CAP_SYS_ADMIN`. Tag with `source: "jni:<package>.<Class>.<method>"`.

## Edge cases

- **Static binaries**: have no dynamic symbol table. Use `objdump -t` for the (full) symbol table if not stripped; otherwise rely on strings + disassembly.
- **Position-independent executables (PIE)**: same as shared objects for analysis purposes.
- **Multi-ABI .so**: each is independent — analyze each. A `mount` import in `lib/arm64-v8a/libfoo.so` is a separate signal from one in `lib/x86_64/libfoo.so`.
- **Binaries with versioned symbols** (e.g. `mount@GLIBC_2.28`): the version is recorded in the signal's `evidence` field but doesn't change the mapping.
- **Linker scripts / bootstrap binaries**: may have minimal symbols. Rely on strings.

## Output (findings.json shape)

```json
{
  "target": "/path/to/target.so",
  "target_type": "elf",
  "arch": "arm64-v8a",
  "is_stripped": false,
  "is_packed": false,
  "needed_libs": ["liblog.so", "libc.so", "libm.so", "libcap.so"],
  "jni_entry_points": [
    "Java_com_example_Foo_nativeMount",
    "Java_com_example_Foo_nativeSetuid"
  ],
  "signals": [
    {
      "kind": "syscall",
      "name": "mount",
      "source": "binary:libfoo.so",
      "evidence": "imported dynamic symbol (UND in .dynsym)",
      "confidence": "ambiguous"
    },
    {
      "kind": "file_path",
      "name": "/dev/mem",
      "source": "binary:libfoo.so",
      "evidence": "string table @ offset 0x1234",
      "confidence": "unambiguous"
    },
    {
      "kind": "needed_lib",
      "name": "libcap.so",
      "source": "binary:libfoo.so",
      "evidence": "DT_NEEDED entry",
      "confidence": "unambiguous"
    }
  ]
}
```
