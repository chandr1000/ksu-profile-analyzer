#!/system/bin/sh
# ============================================================================
# ksu-profile-analyzer — runtime syscall capture helper
# ----------------------------------------------------------------------------
# Push this to your device and run under su to capture strace logs of an
# Android app's actual runtime syscalls. Use this when static analysis was
# inconclusive (packed/obfuscated binary, ambiguous syscalls).
#
# After capture, pull the logs back to your PC and re-invoke the skill with
# --from-strace <log_dir> to merge runtime findings with static findings.
#
# Requirements on device:
#   - Root (via su — strace needs CAP_SYS_PTRACE to attach)
#   - strace binary (most KSU-flashed devices have it in /system/bin/strace
#     or /data/local/tmp/strace; if missing, install busybox or download a
#     static strace binary for your ABI)
#
# Usage:
#   adb push strace_capture.sh /data/local/tmp/
#   adb shell chmod +x /data/local/tmp/strace_capture.sh
#   adb shell su -c '/data/local/tmp/strace_capture.sh com.example.foo [duration_seconds]'
#
# Default duration: 30 seconds. Increase for production apps (e.g. 300 for
# a 5-minute capture) to exercise more code paths.
# ============================================================================

set -eu

PACKAGE_NAME="${1:?Usage: strace_capture.sh <package_name> [duration_seconds]}"
DURATION="${2:-30}"

OUTPUT_DIR="/sdcard/ksu_strace_${PACKAGE_NAME}"
STRACE_BIN="${STRACE_BIN:-strace}"

# Sanity
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must run as root. Use: su -c '$0 $*'"
    exit 1
fi

if ! command -v "$STRACE_BIN" >/dev/null 2>&1; then
    echo "ERROR: $STRACE_BIN not found in PATH."
    echo "Options:"
    echo "  1. Install busybox (most distros include strace):"
    echo "       adb shell su -c 'apt install busybox'   # if your device has apt"
    echo "       adb shell su -c 'busybox --install -s /data/local/tmp/'"
    echo "  2. Download a static strace binary for your ABI and push it:"
    echo "       adb push strace-aarch64 /data/local/tmp/strace"
    echo "       adb shell chmod +x /data/local/tmp/strace"
    echo "       export STRACE_BIN=/data/local/tmp/strace  # in the su shell"
    exit 1
fi

# Find the package's main activity (to launch it after force-stop)
MAIN_ACTIVITY=$(cmd package resolve-activity --brief "$PACKAGE_NAME" 2>/dev/null | tail -1)
if [ -z "$MAIN_ACTIVITY" ]; then
    echo "WARN: couldn't resolve main activity for $PACKAGE_NAME."
    echo "      The app won't be auto-launched. Start it manually after this script begins."
fi

# Prepare output dir
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Force-stop the app so we capture from the start
echo "Force-stopping $PACKAGE_NAME..."
am force-stop "$PACKAGE_NAME" 2>/dev/null || true

# Start strace attached to the launching zygote-fork
# -ff: follow forks, one log file per PID
# -y: print the file path associated with each fd argument (CRITICAL — without
#     this, write(fd, ...) / read(fd, ...) lines don't include the path, and
#     the skill cannot map them to capabilities. E.g. with -y, strace prints
#     `write(3</sys/kernel/config/usb_gadget/g1/UDC>, "", 0)` instead of
#     `write(3, "", 0)`. The fd→path annotation is what makes write/read
#     signals actionable.)
# -e trace=%file,%desc,%network,%process,%signal,%memory,%ipc:
#     filter to interesting syscall classes. %desc is the file-descriptor
#     syscall class (read, write, pwrite, pread, writev, readv, sendfile,
#     splice, copy_file_range, tee, vmsplice) — WITHOUT this class, strace
#     captures openat() but NOT the write() that actually performs the
#     privileged operation. This was a real bug: the previous filter
#     %file,%network,...,%ipc captured 48,889 openat calls but ZERO
#     write/pwrite/writev calls, hiding EACCES denials on write() to
#     configfs /dev nodes that needed CAP_DAC_OVERRIDE.
#     On old strace versions (<5.3) where %desc isn't supported, use the
#     explicit form instead:
#       -e trace=%file,read,write,pwrite,pread,writev,readv,%network,...
#     Or for maximum coverage, use -e trace=all (much larger logs, slower).
# -o: output prefix (strace appends .<pid>)
# -p: attach to existing PID — we'll attach to the app after launch instead

# Strategy: launch the app via `am start`, find its main PID, attach strace.
# Alternative: use `strace -ff -o ... am start ...` to trace the launch itself,
# but this only catches the launch — we want runtime behavior.

echo "Launching $PACKAGE_NAME..."
if [ -n "$MAIN_ACTIVITY" ]; then
    am start -n "$MAIN_ACTIVITY" >/dev/null 2>&1 || true
else
    monkey -p "$PACKAGE_NAME" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
fi

# Wait briefly for the app to start its main process
sleep 2

# Find the main PID
PID=$(pidof "$PACKAGE_NAME" 2>/dev/null | tr ' ' '\n' | head -1)
if [ -z "$PID" ]; then
    echo "ERROR: $PACKAGE_NAME is not running. Launch it manually and re-run."
    exit 1
fi

echo "Found $PACKAGE_NAME PID: $PID"
echo "Attaching strace (duration: ${DURATION}s, output: $OUTPUT_DIR/trace.*)..."

# Attach strace with -ff to follow forks.
# -y is MANDATORY: it annotates every fd argument with the file path
#    (e.g. `write(3</sys/kernel/config/usb_gadget/g1/UDC>, "", 0)`), which
#    is what the downstream strace_analyze.py parser needs to map
#    write/read calls to capabilities.
# -e trace=%file,%desc,%network,%process,%signal,%memory,%ipc:
#    %desc captures read/write/pwrite/pread/writev/readv/sendfile/splice/
#    copy_file_range/tee/vmsplice — without it, strace only captures
#    openat() (the file opens) but NOT the subsequent write()/read() that
#    actually performs the privileged operation and returns EACCES.
# Run in background, kill after DURATION seconds.
"$STRACE_BIN" -ff -y \
    -e trace=%file,%desc,%network,%process,%signal,%memory,%ipc \
    -o "$OUTPUT_DIR/trace" \
    -p "$PID" &
STRACE_PID=$!

# Wait for the duration, then kill strace
echo "Capturing... press Ctrl-C here to stop early."
sleep "$DURATION" || true
kill -INT "$STRACE_PID" 2>/dev/null || true
wait "$STRACE_PID" 2>/dev/null || true

# Show what we got
LOG_COUNT=$(ls "$OUTPUT_DIR"/trace.* 2>/dev/null | wc -l)
TOTAL_LINES=$(cat "$OUTPUT_DIR"/trace.* 2>/dev/null | wc -l)
echo ""
echo "=== Capture complete ==="
echo "Output directory: $OUTPUT_DIR"
echo "Log files: $LOG_COUNT (one per traced PID)"
echo "Total lines: $TOTAL_LINES"
echo ""
echo "Next steps:"
echo "  1. Pull the logs to your PC:"
echo "       adb pull $OUTPUT_DIR ./strace_logs/"
echo "  2. Re-invoke the ksu-profile-analyzer skill with:"
echo "       --from-strace ./strace_logs/"
echo "  The skill will parse these logs and merge runtime findings with"
echo "  the static analysis findings you already have."
