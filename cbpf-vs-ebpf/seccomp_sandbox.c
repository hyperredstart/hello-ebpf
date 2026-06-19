// seccomp_sandbox.c — a "no network" sandbox built from RAW classic BPF (cBPF).
//
// Real-world pattern: this is the same mechanism Docker, Chrome, systemd and
// OpenSSH use to confine processes. We install a seccomp-BPF filter that DENIES
// the socket() syscall, then exec the command you pass — so it physically cannot
// open a network connection. No root needed (that's the whole point of seccomp).
//
// The filter below IS cBPF: a flat list of `struct sock_filter` instructions
// (load / compare / return) — stateless, no maps, allow-or-deny per syscall.
//
// Build:  clang seccomp_sandbox.c -o seccomp_sandbox     (or: cc ... )
// Run:    ./seccomp_sandbox curl -s https://example.com   -> blocked
//         ./seccomp_sandbox cat /etc/hostname             -> allowed (no socket)

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int install_no_network_filter(void) {
    struct sock_filter filter[] = {
        // 1) Load the running architecture from seccomp_data.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#else
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xffffffff, 1, 0),
#endif
        //    Unexpected arch -> syscall numbers can't be trusted -> kill.
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // 2) Load the syscall number.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        // 3) if (nr == socket) return EACCES;  else allow.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    // NO_NEW_PRIVS lets an unprivileged process install a filter safely.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("prctl(NO_NEW_PRIVS)"); return -1; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("prctl(SECCOMP)"); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    if (install_no_network_filter()) return 1;
    fprintf(stderr, "[sandbox] socket() now returns EACCES for: %s\n", argv[1]);
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 127;
}
