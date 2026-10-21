#include "vault.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtEndian>
#include <cassert>
#include <csignal>
#include <cstdio>
#include <sodium.h>
#include <sys/resource.h>

static const QString kCreds = "/usr/bin/systemd-creds";
static const QByteArray kPlain = "{\"entries\":[]}";

static QByteArray readAll(const QString &path)
{
    QFile f(path);
    f.open(QIODevice::ReadOnly);
    return f.readAll();
}

static void writeAll(const QString &path, const QByteArray &data)
{
    QFile f(path);
    f.open(QIODevice::WriteOnly | QIODevice::Truncate);
    f.write(data);
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
    QDir().mkpath(QFileInfo(path).absolutePath());
    writeAll(path, out);
}

static void roundtrip(const QString &path, const QString &creds)
{
    const bool tpm = !creds.isEmpty();
    QString recovery;
    QByteArray plain;
    {
        Vault v(path, creds);
        assert(v.create("correct horse", recovery));
        assert(recovery.size() == 39); // 8 groups of 4 hex digits
        assert(v.usesTpm() == tpm);
        assert(v.save(kPlain));
        assert((QFile::permissions(path) & 0x0077) == 0); // no group/other bits
    }
    {
        Vault v(path, creds);
        QString none;
        assert(v.open("correct horse", plain, none) && plain == kPlain && none.isEmpty());
        assert(v.verifyPassword("correct horse"));
        assert(!v.verifyPassword("wrong"));
        assert(!Vault(path, creds).open("wrong", plain, none));
    }
    {
        // recovery key opens it, then a new password replaces the old one
        Vault v(path, creds);
        assert(!v.openWithRecovery("0000-0000-0000-0000-0000-0000-0000-0000", plain));
        assert(!v.openWithRecovery("not hex", plain));
        assert(v.openWithRecovery(recovery.toLower().replace("-", " "), plain) && plain == kPlain);
        assert(v.setPassword("battery staple", plain));
        assert(v.usesTpm() == tpm);
        QString none;
        assert(Vault(path, creds).open("battery staple", plain, none));
        assert(!Vault(path, creds).open("correct horse", plain, none));
        assert(Vault(path, creds).openWithRecovery(recovery, plain)); // recovery slot survives a password change

        QString fresh;
        assert(!v.resetRecovery("wrong", plain, fresh) && fresh.isEmpty());
        assert(v.resetRecovery("battery staple", plain, fresh) && fresh.size() == 39 && fresh != recovery);
        assert(!Vault(path, creds).openWithRecovery(recovery, plain));
        assert(Vault(path, creds).openWithRecovery(fresh, plain));
        recovery = fresh;
    }
    {
        // any header byte changed is rejected (cheap through the recovery path: no Argon2id)
        const QByteArray good = readAll(path);
        const int header = good.size() - kPlain.size() - 16;
        for (int i = 0; i < header; ++i) {
            QByteArray bad = good;
            bad[i] = bad[i] ^ 0x01;
            writeAll(path, bad);
            assert(!Vault(path, creds).openWithRecovery(recovery, plain));
        }
        for (int n = 0; n < good.size(); n += 7) {
            writeAll(path, good.left(n));
            assert(!Vault(path, creds).openWithRecovery(recovery, plain));
        }
        writeAll(path, good);
    }
    {
        QByteArray bad = readAll(path);
        bad[bad.size() - 1] = bad[bad.size() - 1] ^ 1;
        writeAll(path, bad);
        QString none;
        assert(!Vault(path, creds).open("battery staple", plain, none));
    }
}

// A password change whose save fails must leave both memory and file on the old password.
static void failedSaveKeepsPassword(const QString &path)
{
    QString recovery, none;
    QByteArray plain;
    Vault(path, "").create("old password", recovery);
    Vault v(path, "");
    assert(v.open("old password", plain, none));

    signal(SIGXFSZ, SIG_IGN);
    rlimit lim;
    getrlimit(RLIMIT_FSIZE, &lim);
    const rlim_t soft = lim.rlim_cur;
    lim.rlim_cur = 64; // smaller than any vault file
    setrlimit(RLIMIT_FSIZE, &lim);
    const bool changed = v.setPassword("new password", plain);
    lim.rlim_cur = soft;
    setrlimit(RLIMIT_FSIZE, &lim);

    assert(!changed && !v.error.isEmpty());
    assert(v.verifyPassword("old password"));
    assert(v.save(plain)); // a later autosave must not apply the abandoned password
    assert(Vault(path, "").open("old password", plain, none));
}

int main()
{
    assert(sodium_init() >= 0);
    QTemporaryDir dir;

    roundtrip(dir.filePath("plain/vault.bin"), "");
    const bool tpm = QFile::exists("/dev/tpmrm0") && QFile::exists(kCreds);
    if (tpm) roundtrip(dir.filePath("tpm/vault.bin"), kCreds);
    failedSaveKeepsPassword(dir.filePath("fsize/vault.bin"));

    {
        // a locked vault reports why, instead of an empty error the UI would read as success
        Vault v(dir.filePath("closed/vault.bin"), "");
        assert(!v.verifyPassword("x") && !v.error.isEmpty());
        v.error.clear();
        assert(!v.setPassword("x", kPlain) && !v.error.isEmpty());
    }

    if (tpm) {
        // a TPM that is present but failing is an error, never a silent downgrade to password-only
        const QString path = dir.filePath("tpmfail/vault.bin");
        QString recovery, none;
        QByteArray plain;
        assert(!Vault(path, "/bin/false").create("pw", recovery) && !QFile::exists(path));
        assert(Vault(path, kCreds).create("pw", recovery));
        assert(!Vault(path, "/bin/false").open("pw", plain, none));
        Vault v(path, "/bin/false");
        assert(v.openWithRecovery(recovery, plain));
        assert(!v.setPassword("other", plain) && !v.error.isEmpty());
        Vault after(path, kCreds);
        assert(after.open("pw", plain, none) && after.usesTpm());
    }

    {
        // v1 files are upgraded in place on first open
        const QString path = dir.filePath("v1/vault.bin");
        const QString creds = tpm ? kCreds : QString();
        writeV1(path, "old password", "{\"entries\":[1]}");
        QByteArray plain;
        QString recovery;
        assert(!Vault(path, creds).open("wrong", plain, recovery));
        Vault v(path, creds);
        assert(v.open("old password", plain, recovery) && plain == "{\"entries\":[1]}");
        assert(!recovery.isEmpty() && v.usesTpm() == tpm);
        assert(readAll(path).startsWith("PMV2"));
        QString none;
        assert(Vault(path, creds).open("old password", plain, none) && none.isEmpty());
        assert(Vault(path, creds).openWithRecovery(recovery, plain) && plain == "{\"entries\":[1]}");
    }

    const QString pw = generatePassword(12, true, true, true, true);
    assert(pw.size() == 12);
    assert(generatePassword(8, false, false, true, false).size() == 8);
    assert(generatePassword(8, false, false, false, false).isEmpty());

    printf("ok (tpm %s)\n", tpm ? "tested" : "skipped");
}
