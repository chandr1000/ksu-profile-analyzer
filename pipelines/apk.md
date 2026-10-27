# Pipeline: APK analysis

Extract signals from an Android APK (`.apk` file). The APK is a ZIP archive containing `AndroidManifest.xml`, compiled resources (`resources.arsc`), DEX bytecode (`classes*.dex`), native libraries (`lib/<abi>/*.so`), and assets.

## Inputs

- `target`: absolute path to the `.apk` file

## Tools (must be installed and on PATH)

| Tool | Used for |
|---|---|
| `apktool` (≥2.9) | Decode manifest + smali + resources |
| `jadx` (≥1.5) | Decompile DEX to readable Java (optional but recommended) |
| `aapt2` (or `aapt`) | Dump manifest permissions quickly |
| `unzip` | Extract the APK as a ZIP for native lib access |
| `file` | Identify ELF files in `lib/` |
| `strings` | Pull hardcoded strings from native libs |
| `readelf`, `objdump`, `nm` | Inspect native libs (recurses into `pipelines/binary.md`) |

## Workflow

### 1. Decode manifest permissions

```sh
mkdir -p /home/z/my-project/scripts/_work/<pkg_basename>
cd /home/z/my-project/scripts/_work/<pkg_basename>

# Fast path — permissions only:
aapt2 dump permissions /path/to/target.apk > perms.txt

# Full decode (for smali / asset strings):
apktool d -f -o decoded /path/to/target.apk
```

Parse `perms.txt` lines like `android.permission.INTERNET` and look each one up in `reference/syscall_to_cap.md` (the "AndroidManifest permissions" section).

### 2. Extract native libraries

```sh
mkdir -p native_libs
cd native_libs
unzip -o /path/to/target.apk 'lib/*' -d .
# This creates lib/<abi>/<libname>.so for each ABI
```

For each `lib/<abi>/*.so`, recurse into `pipelines/binary.md` and accumulate signals. Each `.so`'s signals are tagged `source: "apk:lib/<abi>/<libname>.so"`.

### 3. Decompile DEX (optional)

```sh
jadx --no-res -d decompiled /path/to/target.apk
# Or per-DEX:
jadx -d decompiled classes.dex classes2.dex ...
```

Then scan `decompiled/` with ripgrep for Java signals (see "Java / Kotlin source signals" section of `reference/syscall_to_cap.md`).

### 4. Scan smali directly (fallback if jadx fails)

```sh
# The decoded/smali_* directories from apktool contain the smali:
rg --line-number --type=s smali \
  -e 'Runtime\.exec' \
  -e 'ProcessBuilder' \
  -e 'Lcom/topjohnwu/superuser/Shell' \
  -e 'Lcom/topjohnwu/magisk' \
  decoded/smali*
```

### 5. Scan resource strings

```sh
# Pull hardcoded paths / URLs / dev nodes from strings.xml:
rg -e '/dev/' -e '/proc/' -e '/sys/' -e '/data/adb/' \
  decoded/res/values/strings.xml \
  decoded/res/values*/strings.xml
```

Also scan `assets/` for any binaries or scripts:

```sh
file decoded/assets/* 2>/dev/null | grep -E 'ELF|script'
```

### 6. Identify su intent

The single most important signal: does the app actually try to invoke `su`? If yes, `allowSu: true` is justified. If no, the user should be warned that they're about to grant root to an app that doesn't appear to use it.

Signals (in priority order):

| Signal | Source | Confidence |
|---|---|---|
| `Lcom/topjohnwu/superuser/Shell;->su` | smali | unambiguous |
| `Lcom/topjohnwu/superuser/Shell;->cmd` with `useSu=true` | smali | unambiguous |
| `Runtime.exec("su")` | decompiled Java | unambiguous |
| `Runtime.exec(new String[]{"su", ...})` | decompiled Java | unambiguous |
| `ProcessBuilder("su")` | decompiled Java | unambiguous |
| String `"su"` in `.data` section of a `.so` (with surrounding context like `exec*`) | strings | ambiguous |
| String `"/system/xbin/su"` or `"/system/bin/su"` | smali / strings / resources | unambiguous |
| `Lcom/topjohnwu/magisk/MagiskBean` | smali | unambiguous |

### 7. Emit findings.json

Aggregate everything into the standard Findings JSON shape. Each signal gets `kind`, `name`, `source`, `evidence`, and `confidence`. The downstream Stage 4 (mapping) reads this file.

## Edge cases

- **Multi-arch APK**: iterate all `lib/<abi>/*.so` (typically `arm64-v8a`, `armeabi-v7a`, `x86_64`). Don't skip any — even if the user's device only runs one ABI, all native libs may load if the app bundles them.
- **Split APKs** (`.apks` / `.apkm`): unpack the base APK + relevant splits, then merge manifests. The base split is authoritative for permissions.
- **Obfuscated smali** (class names like `a.b.c`): fall back to native lib analysis + manifest. The native libs cannot be obfuscated (they're stripped, not renamed).
- **Packed/encrypted DEX** (e.g. Jiagu, Bangcle): the smali will be empty or contain only a loader stub. Emit a `packed_dex` signal in `findings.json` — this triggers the `strace_capture.sh` recommendation in `analysis.md`.
- **Shared-user-id apps** (`sharedUserId` in manifest): use the shared UID, not the package's own UID. The `currentUid` placeholder instruction in `analysis.md` should mention this.
- **System-signed apps** (`android:sharedUserId="android.uid.system"` or signed with platform key): these get `SYSTEM (1000)` automatically — the Profile should not grant additional caps unless the user explicitly requests them.

## Output (findings.json shape)

```json
{
  "target": "/path/to/target.apk",
  "target_type": "apk",
  "package_name": "com.example.foo",
  "version_name": "1.2.3",
  "version_code": 123,
  "shared_user_id": null,
  "signals": [
    {
      "kind": "android_perm",
      "name": "INTERNET",
      "source": "manifest",
      "evidence": "<uses-permission android:name=\"android.permission.INTERNET\" />",
      "confidence": "unambiguous"
    },
    {
      "kind": "syscall",
      "name": "mount",
      "source": "apk:lib/arm64-v8a/libnative.so",
      "evidence": "imported dynamic symbol",
      "confidence": "ambiguous"
    },
    {
      "kind": "su_invocation",
      "name": "Runtime.exec(\"su\")",
      "source": "apk:classes.dex",
      "evidence": "Lcom/example/RootHelper;->exec()V calls Ljava/lang/Runtime;->exec(Ljava/lang/String;)Lb/c; with const-string \"su\"",
      "confidence": "unambiguous"
    },
    {
      "kind": "file_path",
      "name": "/dev/mem",
      "source": "apk:lib/arm64-v8a/libnative.so",
      "evidence": "string table @ 0x1234",
      "confidence": "unambiguous"
    }
  ]
}
```

## What this pipeline does NOT do

- It does not run the APK in an emulator.
- It does not unpack Jiagu/Bangcle/etc. encrypted DEX (it detects and reports, then defers to strace).
- It does not decode obfuscated Java class names back to their original names (the signal names remain obfuscated in findings.json).
- It does not analyze signed APKs differently from unsigned ones (signing is irrelevant to capabilities).
