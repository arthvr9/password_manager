#include "sandbox.h"
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <cassert>
#include <cstdio>
#include <sys/socket.h>
#include <sys/wait.h>
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

// The sandbox is irreversible, so it runs in a child and the parent cleans up.
int main()
{
    QTemporaryDir dir;
    const QString box = dir.filePath("box");
    QDir().mkpath(box);
    QFile::copy("/usr/bin/true", box + "/true");

    const pid_t pid = fork();
    if (pid == 0) {
        assert(sandbox({box}).isEmpty());
        assert(socket(AF_INET, SOCK_STREAM, 0) == -1);
        assert(socket(AF_INET6, SOCK_DGRAM, 0) == -1);
        const int local = socket(AF_UNIX, SOCK_STREAM, 0);
        assert(local >= 0);
        close(local);

        QFile inside(box + "/file");
        assert(inside.open(QIODevice::WriteOnly) && inside.write("x") == 1);
        inside.close();
        assert(QFile::rename(box + "/file", box + "/renamed")); // QSaveFile does this
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
