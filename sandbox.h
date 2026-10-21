#pragma once
#include <QStringList>

// Restricts this process and every child it spawns, irreversibly:
//   Landlock: files can only be created or written under `writableDirs` (plus /dev/null),
//             and only programs under /usr can be executed
//   seccomp:  no IPv4/IPv6/packet sockets and no io_uring; Unix sockets (X11, D-Bus) still work
// Returns the names of the layers the kernel refused, empty when all are active.
QString sandbox(const QStringList &writableDirs);
