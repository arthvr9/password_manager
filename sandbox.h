#pragma once
#include <QStringList>

// Restricts this process and every child it spawns, irreversibly:
//   Landlock: files can only be created or written under `writableDirs` (plus /dev/null),
//             and only programs under /usr can be executed
//   seccomp:  sockets only of AF_UNIX (X11, D-Bus) and AF_NETLINK; no io_uring, ptrace,
//             process_vm_* or pidfd_getfd
// Landlock only binds threads created after the call: call it before anything starts threads.
// Returns the names of the layers the kernel refused, empty when all are active.
QString sandbox(const QStringList &writableDirs);
