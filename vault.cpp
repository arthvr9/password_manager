#include "vault.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QtEndian>
#include <cstring>
#include <sodium.h>

static constexpr char kMagic[4] = {'P', 'M', 'V', '1'};
static constexpr int kSalt = 16, kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr int kHeader = 4 + kSalt + 8 + 8 + kNonce;

Vault::Vault(QString path) : path_(std::move(path)) {}
Vault::~Vault() { close(); }

bool Vault::exists() const { return QFile::exists(path_); }

void Vault::close()
{
    if (key_) sodium_free(key_); // zeroes before freeing
    key_ = nullptr;
}

bool Vault::derive(QByteArray &password)
{
    close();
    key_ = static_cast<unsigned char *>(sodium_malloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES));
    int rc = crypto_pwhash(key_, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                           password.constData(), password.size(), salt_,
                           ops_, mem_, crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(password.data(), password.size());
    if (rc != 0) {
        close();
        error = "Memória insuficiente para derivar a chave.";
        return false;
    }
    sodium_mprotect_readonly(key_);
    return true;
}

bool Vault::create(QByteArray password)
{
    randombytes_buf(salt_, kSalt);
    ops_ = crypto_pwhash_OPSLIMIT_MODERATE;
    mem_ = crypto_pwhash_MEMLIMIT_MODERATE;
    return derive(password) && save(QByteArray());
}

bool Vault::open(QByteArray password, QByteArray &plain)
{
    QFile f(path_);
    if (!f.open(QIODevice::ReadOnly)) {
        sodium_memzero(password.data(), password.size());
        error = "Não foi possível ler o cofre: " + f.errorString();
        return false;
    }
    const QByteArray data = f.readAll();
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData());
    if (data.size() < kHeader + int(crypto_aead_xchacha20poly1305_ietf_ABYTES) || memcmp(p, kMagic, 4) != 0) {
        sodium_memzero(password.data(), password.size());
        error = "Arquivo do cofre inválido.";
        return false;
    }
    memcpy(salt_, p + 4, kSalt);
    ops_ = qFromLittleEndian<quint64>(p + 4 + kSalt);
    mem_ = qFromLittleEndian<quint64>(p + 4 + kSalt + 8);
    // reject parameters a tampered header could use to stall or exhaust memory
    if (ops_ < crypto_pwhash_OPSLIMIT_MIN || ops_ > 32 || mem_ < crypto_pwhash_MEMLIMIT_MIN || mem_ > (1ull << 32)) {
        sodium_memzero(password.data(), password.size());
        error = "Arquivo do cofre inválido.";
        return false;
    }
    if (!derive(password)) return false;

    const int clen = data.size() - kHeader;
    plain.resize(clen - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(plain.data()), &plen, nullptr,
            p + kHeader, clen, p, kHeader, p + kHeader - kNonce, key_) != 0) {
        close();
        plain.clear();
        error = "Senha incorreta.";
        return false;
    }
    return true;
}

bool Vault::save(const QByteArray &plain)
{
    if (!key_) return false;
    QByteArray out(kHeader + plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
    auto *p = reinterpret_cast<unsigned char *>(out.data());
    memcpy(p, kMagic, 4);
    memcpy(p + 4, salt_, kSalt);
    qToLittleEndian<quint64>(ops_, p + 4 + kSalt);
    qToLittleEndian<quint64>(mem_, p + 4 + kSalt + 8);
    randombytes_buf(p + kHeader - kNonce, kNonce);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        p + kHeader, nullptr, reinterpret_cast<const unsigned char *>(plain.constData()), plain.size(),
        p, kHeader, nullptr, p + kHeader - kNonce, key_);

    const QString dir = QFileInfo(path_).absolutePath();
    QDir().mkpath(dir);
    QFile::setPermissions(dir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    // atomic replace: a crash mid-write never leaves a truncated vault
    QSaveFile f(path_);
    if (!f.open(QIODevice::WriteOnly)) {
        error = "Não foi possível gravar o cofre: " + f.errorString();
        return false;
    }
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    f.write(out);
    if (!f.commit()) {
        error = "Não foi possível gravar o cofre: " + f.errorString();
        return false;
    }
    return true;
}

QString generatePassword(int length, bool upper, bool lower, bool digits, bool symbols)
{
    QList<QByteArray> sets;
    if (upper) sets << "ABCDEFGHJKLMNPQRSTUVWXYZ";
    if (lower) sets << "abcdefghijkmnopqrstuvwxyz";
    if (digits) sets << "23456789";
    if (symbols) sets << "!@#$%&*-_=+?.,:;";
    if (sets.isEmpty() || length < sets.size()) return {};
    const QByteArray all = sets.join();

    // rejection sampling: retry until every chosen class appears at least once
    for (;;) {
        QByteArray out(length, '\0');
        for (char &c : out) c = all[randombytes_uniform(all.size())];
        bool ok = true;
        for (const QByteArray &s : sets) {
            bool hit = false;
            for (char c : out) hit = hit || s.contains(c);
            ok = ok && hit;
        }
        if (ok) return QString::fromLatin1(out);
    }
}
