#include "vault.h"
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtEndian>
#include <cassert>
#include <cstdio>
#include <sodium.h>

static void flipLastByte(const QString &path)
{
    QFile f(path);
    f.open(QIODevice::ReadWrite);
    QByteArray d = f.readAll();
    d[d.size() - 1] = d[d.size() - 1] ^ 1;
    f.seek(0);
    f.write(d);
}

// Writes a vault in the original v1 layout: Argon2id output used directly as the data key.
static void writeV1(const QString &path, const QByteArray &password, const QByteArray &plain)
{
    unsigned char h[4 + 16 + 8 + 8 + 24], key[32];
    memcpy(h, "PMV1", 4);
    randombytes_buf(h + 4, 16);
    qToLittleEndian<quint64>(crypto_pwhash_OPSLIMIT_INTERACTIVE, h + 20);
    qToLittleEndian<quint64>(crypto_pwhash_MEMLIMIT_INTERACTIVE, h + 28);
    randombytes_buf(h + 36, 24);
    assert(crypto_pwhash(key, 32, password.constData(), password.size(), h + 4, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13) == 0);
    QByteArray out(reinterpret_cast<char *>(h), sizeof h);
    out.resize(sizeof h + plain.size() + 16);
    crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(out.data()) + sizeof h, nullptr,
                                               reinterpret_cast<const unsigned char *>(plain.constData()),
                                               plain.size(), h, sizeof h, nullptr, h + 36, key);
    QFile f(path);
    f.open(QIODevice::WriteOnly);
    f.write(out);
}

static void roundtrip(const QString &path, bool tpm)
{
    QString recovery;
    QByteArray plain;
    {
        Vault v(path, tpm);
        assert(v.create("correct horse", recovery));
        assert(recovery.size() == 39); // 8 groups of 4 hex digits
        assert(v.usesTpm() == tpm);
        assert(v.save("{\"entries\":[]}"));
        assert((QFile::permissions(path) & 0x0077) == 0); // no group/other bits
    }
    {
        Vault v(path, tpm);
        QString none;
        assert(v.open("correct horse", plain, none) && plain == "{\"entries\":[]}" && none.isEmpty());
        assert(v.verifyPassword("correct horse"));
        assert(!v.verifyPassword("wrong"));
        assert(!Vault(path, tpm).open("wrong", plain, none));
    }
    {
        // recovery key opens it, then a new password replaces the old one
        Vault v(path, tpm);
        assert(!v.openWithRecovery("0000-0000-0000-0000-0000-0000-0000-0000", plain));
        assert(!v.openWithRecovery("not hex", plain));
        assert(v.openWithRecovery(recovery.toLower().replace("-", " "), plain) && plain == "{\"entries\":[]}");
        assert(v.setPassword("battery staple"));
        assert(v.save(plain));
        QString none;
        assert(Vault(path, tpm).open("battery staple", plain, none));
        assert(!Vault(path, tpm).open("correct horse", plain, none));
        assert(Vault(path, tpm).openWithRecovery(recovery, plain)); // recovery slot survives a password change
    }
    flipLastByte(path);
    QString none;
    assert(!Vault(path, tpm).open("battery staple", plain, none));
}

int main()
{
    assert(sodium_init() >= 0);
    QTemporaryDir dir;

    roundtrip(dir.filePath("plain/vault.bin"), false);
    const bool tpm = QFile::exists("/dev/tpmrm0") && QFile::exists("/usr/bin/systemd-creds");
    if (tpm) roundtrip(dir.filePath("tpm/vault.bin"), true);

    {
        // v1 files are upgraded in place on first open
        const QString path = dir.filePath("v1/vault.bin");
        QDir().mkpath(dir.path() + "/v1");
        writeV1(path, "old password", "{\"entries\":[1]}");
        QByteArray plain;
        QString recovery;
        assert(!Vault(path, tpm).open("wrong", plain, recovery));
        assert(Vault(path, tpm).open("old password", plain, recovery) && plain == "{\"entries\":[1]}");
        assert(!recovery.isEmpty());
        QFile f(path);
        f.open(QIODevice::ReadOnly);
        assert(f.read(4) == "PMV2");
        QString none;
        assert(Vault(path, tpm).open("old password", plain, none) && none.isEmpty());
        assert(Vault(path, tpm).openWithRecovery(recovery, plain) && plain == "{\"entries\":[1]}");
    }

    const QString pw = generatePassword(12, true, true, true, true);
    assert(pw.size() == 12);
    assert(generatePassword(8, false, false, true, false).size() == 8);
    assert(generatePassword(8, false, false, false, false).isEmpty());

    printf("ok (tpm %s)\n", tpm ? "tested" : "skipped");
}
