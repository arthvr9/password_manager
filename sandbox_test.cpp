#include "sandbox.h"
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QTemporaryDir>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

static int run(const QString &path)
{
    const QByteArray p = QFile::encodeName(path);
    const pid_t pid = fork();
    if (pid == 0) {
        execl(p.constData(), p.constData(), nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool socketDenied(int family, int type)
{
    const int fd = socket(family, type, 0);
    if (fd >= 0) close(fd);
    return fd == -1 && errno == EACCES;
}

static bool socketAllowed(int family, int type)
{
    const int fd = socket(family, type, 0);
    if (fd >= 0) close(fd);
    return fd >= 0;
}

static void checkNetwork()
{
    assert(socketDenied(AF_INET, SOCK_STREAM));
    assert(socketDenied(AF_INET6, SOCK_DGRAM));
    assert(socketDenied(AF_PACKET, SOCK_RAW));
    assert(socketDenied(43 /* AF_SMC: falls back to TCP */, SOCK_STREAM));
    assert(socketAllowed(AF_UNIX, SOCK_STREAM));
    assert(socketAllowed(AF_NETLINK, SOCK_RAW));
}

// The sandbox is irreversible, so it runs in a child and the parent cleans up.
int main()
{
    QTemporaryDir dir;
    const QString box = dir.filePath("box");
    assert(QDir().mkpath(box));
    assert(QFile::copy("/usr/bin/true", box + "/true"));
    assert(run(box + "/true") == 0); // runnable before the sandbox, so a 127 later means denied

    const pid_t pid = fork();
    if (pid == 0) {
        // a thread that exists before the sandbox still gets the seccomp filter (TSYNC)
        std::atomic<int> stage{0};
        std::thread early([&] {
            while (stage == 0) usleep(1000);
            checkNetwork();
            stage = 2;
        });

        assert(sandbox({box}).isEmpty());
        stage = 1;
        early.join();
        assert(stage == 2);
        checkNetwork();

        assert(syscall(SYS_io_uring_setup, 1, nullptr) == -1 && errno == ENOSYS);
        assert(syscall(SYS_io_uring_enter, -1, 0, 0, 0, nullptr, 0) == -1 && errno == ENOSYS);
        assert(syscall(SYS_io_uring_register, -1, 0, nullptr, 0) == -1 && errno == ENOSYS);
        assert(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1 && errno == EPERM);
        assert(syscall(SYS_process_vm_readv, getppid(), nullptr, 0, nullptr, 0, 0) == -1 && errno == EPERM);
        assert(syscall(SYS_process_vm_writev, getppid(), nullptr, 0, nullptr, 0, 0) == -1 && errno == EPERM);
        assert(syscall(SYS_pidfd_getfd, -1, 0, 0) == -1 && errno == EPERM);

        QSaveFile save(box + "/vault.bin"); // same path the app takes: temp file, then rename
        assert(save.open(QIODevice::WriteOnly) && save.write("x") == 1 && save.commit());
        assert(save.open(QIODevice::WriteOnly) && save.write("y") == 1 && save.commit());
        QFile outside(dir.filePath("outside"));
        assert(!outside.open(QIODevice::WriteOnly));
        QFile devnull("/dev/null");
        assert(devnull.open(QIODevice::WriteOnly));

        assert(run("/usr/bin/true") == 0);
        assert(run(box + "/true") == 127); // exec outside /usr is denied
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("ok");
}
