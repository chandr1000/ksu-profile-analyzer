# Expected output — strace-sample

Running `python3 scripts/strace_analyze.py examples/strace-sample/` should
produce 11 unique signals (aggregated, with counts where the same signal
appears multiple times):

| # | kind | name | implied caps |
|---|---|---|---|
| 1 | su_invocation | execve(/system/xbin/su) | (sets allowSu) |
| 2 | syscall | mount | CAP_SYS_ADMIN |
| 3 | syscall | setuid | CAP_SETUID |
| 4 | syscall | ptrace | CAP_SYS_PTRACE |
| 5 | syscall | socket(AF_PACKET, SOCK_RAW) | CAP_NET_RAW + group 3004 |
| 6 | syscall | bind(port=80) | CAP_NET_BIND_SERVICE |
| 7 | file_path | /dev/mem | CAP_SYS_RAWIO |
| 8 | syscall | bpf | CAP_BPF |
| 9 | syscall | setsockopt(SO_MARK) | CAP_NET_ADMIN + group 3005 |
| 10 | syscall | setxattr | CAP_SETFCAP |
| 11 | syscall | clone(CLONE_NEWNS\|CLONE_NEWPID) | CAP_SYS_ADMIN |

Note: signal #11 in the trace (`write(3, "", 4096) = 0`) is a write WITHOUT
the `-y` fd→path annotation, so it should produce NO signal (fd number alone
is useless). This is a deliberate negative test case — if the parser starts
producing a signal for it, the `-y` annotation requirement is broken.

This expected-output file documents the regression baseline. CI should
re-run the parser against this sample and verify all 11 signals are detected
(in the same order or sorted) with the same implied caps. If a future
change to `strace_analyze.py` regresses detection, the diff against this
baseline will surface it.
