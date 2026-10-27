package com.example.foo;

import com.topjohnwu.superuser.Shell;

import java.io.File;
import java.io.IOException;

// Tiny demo Android app source used by the smoke test.
// Exercises:
//   - 3 AndroidManifest permissions (INTERNET, CHANGE_NETWORK_STATE,
//     READ_EXTERNAL_STORAGE)
//   - libsu `Shell.su(...)` invocation → sets allowSu=true
//   - `Runtime.getRuntime().exec("su")` invocation → sets allowSu=true
//   - JNI native method declaration (`nativeMount`) → triggers
//     recursion into binary pipeline for libfoo_native.so
//   - Hardcoded privileged paths (`/dev/mem`, `/proc/kcore`) →
//     CAP_SYS_RAWIO
public class MainActivity {
    static {
        System.loadLibrary("foo_native");
    }

    public native int nativeMount(String source, String target);

    public void runAsRoot() throws IOException {
        Shell.su("mount -t tmpfs tmpfs /mnt/foo").exec();
        Runtime.getRuntime().exec("su");
    }

    public void openPrivilegedPaths() {
        File f = new File("/dev/mem");
        File kcore = new File("/proc/kcore");
    }
}
