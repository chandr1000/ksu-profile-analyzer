#include <jni.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Native code for the smoke-test demo. Exercises:
//   - mount() → CAP_SYS_ADMIN
//   - ptrace() → CAP_SYS_PTRACE
//   - setuid() → CAP_SETUID
//   - bind() to privileged port 80 → CAP_NET_BIND_SERVICE
// (The binary pipeline would extract these via `nm -D --undefined-only`
//  once this is compiled into a .so and bundled in an APK's lib/ dir.
//  For the repo pipeline, the ripgrep patterns catch them directly in
//  the source.)
JNIEXPORT jint JNICALL
Java_com_example_foo_MainActivity_nativeMount(JNIEnv *env, jobject thiz, jstring src, jstring tgt) {
    if (mount("/dev/zero", "/mnt/foo", "tmpfs", 0, NULL) != 0) {
        return -1;
    }
    ptrace(PTRACE_ATTACH, 1234, NULL, NULL);
    setuid(0);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_port = htons(80);
    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    return 0;
}
