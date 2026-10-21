#include "sandbox.h"
#include <QFile>
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static bool landlock(const QStringList &writableDirs)
{
    const int abi = syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return false;

    const __u64 fileWrite = LANDLOCK_ACCESS_FS_WRITE_FILE | (abi >= 3 ? LANDLOCK_ACCESS_FS_TRUNCATE : 0);
    const __u64 dirWrite = fileWrite | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                           LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                           (abi >= 2 ? LANDLOCK_ACCESS_FS_REFER : 0);
    landlock_ruleset_attr attr{};
    attr.handled_access_fs = dirWrite | LANDLOCK_ACCESS_FS_EXECUTE;
    const int ruleset = syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (ruleset < 0) return false;

    auto allow = [ruleset](const QByteArray &path, __u64 access) {
        const int fd = open(path.constData(), O_PATH | O_CLOEXEC);
        if (fd < 0) return false;
        landlock_path_beneath_attr rule{access, fd};
        const bool ok = syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) == 0;
        close(fd);
        return ok;
    };
    // a missing vault dir rule would make every save fail; better to report Landlock as refused
    bool ok = true;
    for (const QString &dir : writableDirs) ok = allow(QFile::encodeName(dir), dirWrite) && ok;
    allow("/dev/null", fileWrite);
    allow("/usr", LANDLOCK_ACCESS_FS_EXECUTE); // systemd-creds

    ok = ok && syscall(SYS_landlock_restrict_self, ruleset, 0) == 0;
    close(ruleset);
    return ok;
}

// Landlock only covers TCP on this kernel generation, so the network is cut at socket(), with an
// allowlist: families like AF_SMC fall back to plain TCP. Also blocks the calls that could borrow
// a socket or memory from another same-user process (Landlock blocks them too, when present).
static bool noNetwork()
{
#if defined(__x86_64__)
    constexpr __u32 arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    constexpr __u32 arch = AUDIT_ARCH_AARCH64;
#else
    return false;
#endif
    sock_filter filter[] = {
        // a foreign ABI (e.g. 32-bit int 0x80) would see different syscall numbers: kill
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        // jump offsets count instructions skipped; sandbox_test checks every branch
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 13, 0), // io_uring opens sockets without socket()
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_enter, 12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_register, 11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_process_vm_readv, 10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_process_vm_writev, 9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pidfd_getfd, 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 2, 0),    // X11, D-Bus
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 1, 0), // kernel only, never leaves the machine
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    sock_fprog prog{sizeof filter / sizeof filter[0], filter};
    // TSYNC: also filter threads that already exist (main() runs this before any, but cheap insurance)
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0;
}

QString sandbox(const QStringList &writableDirs)
{
    // required by both layers; also stops children from gaining privileges through setuid binaries
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return "Landlock, seccomp";
    QStringList refused;
    if (!landlock(writableDirs)) refused << "Landlock";
    if (!noNetwork()) refused << "seccomp";
    return refused.join(", ");
}
