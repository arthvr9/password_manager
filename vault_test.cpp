#include "vault.h"
#include <QFile>
#include <QTemporaryDir>
#include <cassert>
#include <cstdio>
#include <sodium.h>

int main()
{
    assert(sodium_init() >= 0);
    QTemporaryDir dir;
    const QString path = dir.filePath("v/vault.bin");

    {
        Vault v(path);
        assert(v.create("correct horse"));
        assert(v.save("{\"entries\":[]}"));
        assert((QFile::permissions(path) & 0x0077) == 0); // no group/other bits
    }
    {
        Vault v(path);
        QByteArray plain;
        assert(v.open("correct horse", plain) && plain == "{\"entries\":[]}");
        assert(!Vault(path).open("wrong", plain));
    }
    {
        QFile f(path);
        f.open(QIODevice::ReadWrite);
        QByteArray d = f.readAll();
        d[d.size() - 1] = d[d.size() - 1] ^ 1;
        f.seek(0);
        f.write(d);
        f.close();
        QByteArray plain;
        assert(!Vault(path).open("correct horse", plain));
    }

    const QString pw = generatePassword(12, true, true, true, true);
    assert(pw.size() == 12);
    assert(generatePassword(8, false, false, true, false).size() == 8);
    assert(generatePassword(8, false, false, false, false).isEmpty());

    puts("ok");
}
