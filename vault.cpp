#include "vault.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSaveFile>
#include <QtEndian>
#include <cstring>
#include <memory>
#include <sodium.h>

static constexpr int kSalt = 16, kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr int kKey = 32, kTag = crypto_aead_xchacha20poly1305_ietf_ABYTES;
static constexpr int kSlot = kNonce + kKey + kTag, kRecovery = 16, kMaxCred = 8192;
static constexpr int kV1Header = 4 + kSalt + 8 + 8 + kNonce;
static const char *kSealError = "Não foi possível selar a chave no TPM. Tente de novo.";
static const char *kLocked = "O cofre está bloqueado.";
static const char *kTpmError = "Não foi possível usar o TPM desta máquina. Se o cofre veio de outro computador "
                               "ou o TPM foi limpo, use a chave de recuperação.";

static_assert(kSlot == 72, "slot size is part of the file format, see vault.h");

// ---------- systemd-creds ----------

static std::unique_ptr<QProcess> creds(const QString &bin, const QStringList &args, const QByteArray &input)
{
    auto p = std::make_unique<QProcess>();
    p->start(bin, QStringList{"--user"} + args);
    if (p->waitForStarted(5000)) {
        p->write(input);
        p->closeWriteChannel();
    }
    return p;
}

static bool credsFinish(QProcess &p, QByteArray &out)
{
    const bool ok = p.waitForFinished(30000) && p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
    out = p.readAllStandardOutput();
    return ok;
}

// No PCR binding on purpose: a firmware update would otherwise lock the vault.
static std::unique_ptr<QProcess> seal(const QString &bin, const unsigned char *secret)
{
    QByteArray input(reinterpret_cast<const char *>(secret), kKey);
    auto p = creds(bin, {"encrypt", "--with-key=tpm2+host", "--tpm2-pcrs=", "--name=pass-manager", "-", "-"}, input);
    sodium_memzero(input.data(), input.size());
    return p;
}

// A blob parse() would reject must never reach save(), or both slots become unreachable.
static bool sealFinish(QProcess &p, QByteArray &cred)
{
    return credsFinish(p, cred) && !cred.isEmpty() && cred.size() <= kMaxCred;
}

// ---------- key wrapping ----------

static void wrap(const unsigned char *kek, const unsigned char *key, unsigned char *slot)
{
    randombytes_buf(slot, kNonce);
    crypto_aead_xchacha20poly1305_ietf_encrypt(slot + kNonce, nullptr, key, kKey, nullptr, 0, nullptr, slot, kek);
}

static bool unwrap(const unsigned char *kek, const unsigned char *slot, unsigned char *key)
{
    return crypto_aead_xchacha20poly1305_ietf_decrypt(key, nullptr, nullptr, slot + kNonce, kKey + kTag, nullptr, 0,
                                                      slot, kek) == 0;
}

static unsigned char *allocKey()
{
    return static_cast<unsigned char *>(sodium_malloc(kKey));
}

// ---------- Vault ----------

Vault::Vault(QString path, QString credsBin) : path_(std::move(path)), creds_(std::move(credsBin)) {}
Vault::~Vault() { close(); }

bool Vault::exists() const { return QFile::exists(path_); }

bool Vault::tpmPresent() const
{
    return !creds_.isEmpty() && QFile::exists(creds_) && QFile::exists("/dev/tpmrm0");
}

void Vault::close()
{
    if (key_) sodium_free(key_); // zeroes before freeing
    key_ = nullptr;
}

bool Vault::read(QByteArray &data)
{
    QFile f(path_);
    if (!f.open(QIODevice::ReadOnly)) {
        error = "Não foi possível ler o cofre: " + f.errorString();
        return false;
    }
    data = f.readAll();
    return true;
}

int Vault::parse(const QByteArray &data)
{
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData());
    const qsizetype n = data.size();
    int off = 4 + kSalt + 8 + 8 + 4;
    if (n < off || memcmp(p, "PMV2", 4) != 0) return 0;
    memcpy(pwSalt_, p + 4, kSalt);
    ops_ = qFromLittleEndian<quint64>(p + 4 + kSalt);
    mem_ = qFromLittleEndian<quint64>(p + 4 + kSalt + 8);
    const quint32 credLen = qFromLittleEndian<quint32>(p + 4 + kSalt + 16);
    // reject parameters a tampered header could use to stall or exhaust memory
    if (ops_ < crypto_pwhash_OPSLIMIT_MIN || ops_ > 32 || mem_ < crypto_pwhash_MEMLIMIT_MIN || mem_ > (1ull << 32) ||
        credLen > kMaxCred || n < off + qsizetype(credLen) + kSlot + kSalt + kSlot + kNonce + kTag)
        return 0;
    cred_ = data.mid(off, credLen);
    off += credLen;
    memcpy(pwSlot_, p + off, kSlot);
    off += kSlot;
    memcpy(recSalt_, p + off, kSalt);
    off += kSalt;
    memcpy(recSlot_, p + off, kSlot);
    off += kSlot;
    return off + kNonce;
}

bool Vault::passwordKek(QByteArray &password, unsigned char *kek)
{
    // unseal runs in parallel with Argon2id; both take about a second
    std::unique_ptr<QProcess> tpm;
    if (!cred_.isEmpty()) tpm = creds(creds_, {"decrypt", "--name=pass-manager", "-", "-"}, cred_);

    unsigned char pwKey[kKey];
    const int rc = crypto_pwhash(pwKey, kKey, password.constData(), password.size(), pwSalt_, ops_, mem_,
                                 crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(password.data(), password.size());
    if (rc != 0) {
        error = "Memória insuficiente para derivar a chave.";
        return false;
    }
    QByteArray secret;
    if (tpm && (!credsFinish(*tpm, secret) || secret.size() != kKey)) {
        sodium_memzero(pwKey, kKey);
        sodium_memzero(secret.data(), secret.size());
        error = kTpmError;
        return false;
    }
    crypto_generichash(kek, kKey, reinterpret_cast<const unsigned char *>(secret.constData()), secret.size(), pwKey,
                       kKey);
    sodium_memzero(pwKey, kKey);
    sodium_memzero(secret.data(), secret.size());
    return true;
}

bool Vault::setPassword(QByteArray password, const QByteArray &plain)
{
    if (!key_) {
        sodium_memzero(password.data(), password.size());
        error = kLocked;
        return false;
    }
    unsigned char salt[kSalt], secret[kKey], pwKey[kKey], kek[kKey];
    randombytes_buf(salt, kSalt);
    randombytes_buf(secret, kKey);
    auto sealing = tpmPresent() ? seal(creds_, secret) : nullptr;

    const quint64 ops = crypto_pwhash_OPSLIMIT_MODERATE, mem = crypto_pwhash_MEMLIMIT_MODERATE;
    const int rc = crypto_pwhash(pwKey, kKey, password.constData(), password.size(), salt, ops, mem,
                                 crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(password.data(), password.size());
    if (rc != 0) {
        sodium_memzero(secret, kKey);
        error = "Memória insuficiente para derivar a chave.";
        return false;
    }

    QByteArray cred;
    const bool sealFailed = sealing && !sealFinish(*sealing, cred);
    if (!sealFailed)
        crypto_generichash(kek, kKey, cred.isEmpty() ? nullptr : secret, cred.isEmpty() ? 0 : kKey, pwKey, kKey);
    sodium_memzero(secret, kKey);
    sodium_memzero(pwKey, kKey);
    if (sealFailed) {
        error = kSealError;
        return false;
    }

    // keep the old slot so a failed save leaves memory matching the file
    unsigned char oldSalt[kSalt], oldSlot[kSlot];
    memcpy(oldSalt, pwSalt_, kSalt);
    memcpy(oldSlot, pwSlot_, kSlot);
    const quint64 oldOps = ops_, oldMem = mem_;
    const QByteArray oldCred = cred_;

    memcpy(pwSalt_, salt, kSalt);
    ops_ = ops;
    mem_ = mem;
    cred_ = cred;
    wrap(kek, key_, pwSlot_);
    sodium_memzero(kek, kKey);
    if (save(plain)) return true;

    memcpy(pwSalt_, oldSalt, kSalt);
    memcpy(pwSlot_, oldSlot, kSlot);
    ops_ = oldOps;
    mem_ = oldMem;
    cred_ = oldCred;
    return false;
}

void Vault::newRecovery(QString &recovery)
{
    unsigned char rec[kRecovery], kek[kKey];
    char hex[kRecovery * 2 + 1];
    randombytes_buf(rec, kRecovery);
    randombytes_buf(recSalt_, kSalt);
    crypto_generichash(kek, kKey, recSalt_, kSalt, rec, kRecovery);
    wrap(kek, key_, recSlot_);
    sodium_bin2hex(hex, sizeof hex, rec, kRecovery);
    recovery.clear();
    for (int i = 0; i < kRecovery * 2; i += 4) recovery += (i ? "-" : "") + QString::fromLatin1(hex + i, 4).toUpper();
    sodium_memzero(rec, kRecovery);
    sodium_memzero(kek, kKey);
    sodium_memzero(hex, sizeof hex);
}

bool Vault::create(QByteArray password, QString &recovery)
{
    close();
    key_ = allocKey();
    if (!key_) {
        error = "Memória insuficiente.";
        return false;
    }
    randombytes_buf(key_, kKey);
    sodium_mprotect_readonly(key_);
    newRecovery(recovery); // before setPassword, whose save() writes the recovery slot too
    if (!setPassword(std::move(password), QByteArray())) {
        close();
        recovery.clear();
        return false;
    }
    return true;
}

bool Vault::decryptData(const QByteArray &data, int headerLen, QByteArray &plain)
{
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData());
    const qsizetype clen = data.size() - headerLen;
    plain.resize(clen - kTag);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char *>(plain.data()), nullptr, nullptr,
                                                   p + headerLen, clen, p, headerLen, p + headerLen - kNonce,
                                                   key_) != 0) {
        close();
        plain.clear();
        error = "O arquivo do cofre foi alterado ou está corrompido.";
        return false;
    }
    return true;
}

bool Vault::open(QByteArray password, QByteArray &plain, QString &recovery)
{
    close(); // parse() overwrites header fields; never leave them mismatched with an open key
    recovery.clear();
    QByteArray data;
    if (!read(data)) {
        sodium_memzero(password.data(), password.size());
        return false;
    }
    if (data.startsWith("PMV1")) return openV1(data, password, plain, recovery);

    const int h = parse(data);
    if (!h) {
        sodium_memzero(password.data(), password.size());
        error = "Arquivo do cofre inválido.";
        return false;
    }
    unsigned char kek[kKey];
    if (!passwordKek(password, kek)) return false;
    close();
    key_ = allocKey();
    const bool ok = key_ && unwrap(kek, pwSlot_, key_);
    sodium_memzero(kek, kKey);
    if (!ok) {
        close();
        error = "Senha incorreta.";
        return false;
    }
    sodium_mprotect_readonly(key_);
    return decryptData(data, h, plain);
}

bool Vault::openWithRecovery(const QString &recovery, QByteArray &plain)
{
    close();
    QByteArray data;
    if (!read(data)) return false;
    const int h = parse(data);
    if (!h) {
        error = data.startsWith("PMV1") ? "Este cofre é do formato antigo e não tem chave de recuperação."
                                        : "Arquivo do cofre inválido.";
        return false;
    }
    QByteArray hex = recovery.toLatin1();
    hex.removeIf([](char c) { return c == '-' || c == ' '; });
    unsigned char rec[kRecovery], kek[kKey];
    size_t len = 0;
    const int rc = sodium_hex2bin(rec, kRecovery, hex.constData(), hex.size(), nullptr, &len, nullptr);
    sodium_memzero(hex.data(), hex.size());
    if (rc != 0 || len != kRecovery) {
        sodium_memzero(rec, kRecovery);
        error = "Chave de recuperação inválida.";
        return false;
    }
    crypto_generichash(kek, kKey, recSalt_, kSalt, rec, kRecovery);
    sodium_memzero(rec, kRecovery);
    close();
    key_ = allocKey();
    const bool ok = key_ && unwrap(kek, recSlot_, key_);
    sodium_memzero(kek, kKey);
    if (!ok) {
        close();
        error = "Chave de recuperação incorreta.";
        return false;
    }
    sodium_mprotect_readonly(key_);
    return decryptData(data, h, plain);
}

bool Vault::verifyPassword(QByteArray password)
{
    if (!key_) {
        sodium_memzero(password.data(), password.size());
        error = kLocked;
        return false;
    }
    unsigned char kek[kKey], k[kKey];
    if (!passwordKek(password, kek)) return false;
    const bool ok = unwrap(kek, pwSlot_, k) && sodium_memcmp(k, key_, kKey) == 0;
    sodium_memzero(kek, kKey);
    sodium_memzero(k, kKey);
    if (!ok) error = "Senha atual incorreta.";
    return ok;
}

// v1: the Argon2id output was the data key. Decrypt, then rewrite as v2 reusing that same
// Argon2id output (same salt and params) as the password key, so no second hash is needed.
bool Vault::openV1(const QByteArray &data, QByteArray &password, QByteArray &plain, QString &recovery)
{
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData());
    if (data.size() < kV1Header + kTag) {
        sodium_memzero(password.data(), password.size());
        error = "Arquivo do cofre inválido.";
        return false;
    }
    unsigned char salt[kSalt], pwKey[kKey];
    memcpy(salt, p + 4, kSalt);
    const quint64 ops = qFromLittleEndian<quint64>(p + 4 + kSalt);
    const quint64 mem = qFromLittleEndian<quint64>(p + 4 + kSalt + 8);
    if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > 32 || mem < crypto_pwhash_MEMLIMIT_MIN || mem > (1ull << 32)) {
        sodium_memzero(password.data(), password.size());
        error = "Arquivo do cofre inválido.";
        return false;
    }
    const int rc = crypto_pwhash(pwKey, kKey, password.constData(), password.size(), salt, ops, mem,
                                 crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(password.data(), password.size());
    if (rc != 0) {
        error = "Memória insuficiente para derivar a chave.";
        return false;
    }
    const qsizetype clen = data.size() - kV1Header;
    plain.resize(clen - kTag);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char *>(plain.data()), nullptr, nullptr,
                                                   p + kV1Header, clen, p, kV1Header, p + kV1Header - kNonce,
                                                   pwKey) != 0) {
        sodium_memzero(pwKey, kKey);
        plain.clear();
        error = "Senha incorreta.";
        return false;
    }

    close();
    key_ = allocKey();
    if (!key_) {
        sodium_memzero(pwKey, kKey);
        error = "Memória insuficiente.";
        return false;
    }
    randombytes_buf(key_, kKey);
    sodium_mprotect_readonly(key_);

    unsigned char secret[kKey], kek[kKey];
    randombytes_buf(secret, kKey);
    QByteArray cred;
    if (tpmPresent() && !sealFinish(*seal(creds_, secret), cred)) {
        sodium_memzero(secret, kKey);
        sodium_memzero(pwKey, kKey);
        close();
        sodium_memzero(plain.data(), plain.size());
        plain.clear();
        error = kSealError;
        return false;
    }
    crypto_generichash(kek, kKey, cred.isEmpty() ? nullptr : secret, cred.isEmpty() ? 0 : kKey, pwKey, kKey);
    memcpy(pwSalt_, salt, kSalt);
    ops_ = ops;
    mem_ = mem;
    cred_ = cred;
    wrap(kek, key_, pwSlot_);
    sodium_memzero(secret, kKey);
    sodium_memzero(pwKey, kKey);
    sodium_memzero(kek, kKey);

    newRecovery(recovery);
    // ponytail: a failed save here keeps the v1 file and refuses to open; the user retries once the disk is fixed
    if (!save(plain)) {
        close();
        recovery.clear();
        sodium_memzero(plain.data(), plain.size());
        plain.clear();
        return false;
    }
    return true;
}

static void put(QByteArray &out, const void *p, int n) { out.append(static_cast<const char *>(p), n); }

bool Vault::save(const QByteArray &plain)
{
    if (!key_) return false;
    QByteArray out;
    char num[8];
    out.append("PMV2", 4);
    put(out, pwSalt_, kSalt);
    qToLittleEndian<quint64>(ops_, num);
    put(out, num, 8);
    qToLittleEndian<quint64>(mem_, num);
    put(out, num, 8);
    qToLittleEndian<quint32>(quint32(cred_.size()), num);
    put(out, num, 4);
    out.append(cred_);
    put(out, pwSlot_, kSlot);
    put(out, recSalt_, kSalt);
    put(out, recSlot_, kSlot);
    out.resize(out.size() + kNonce);
    const int h = out.size();
    randombytes_buf(out.data() + h - kNonce, kNonce);
    out.resize(h + plain.size() + kTag);
    auto *p = reinterpret_cast<unsigned char *>(out.data());
    crypto_aead_xchacha20poly1305_ietf_encrypt(p + h, nullptr, reinterpret_cast<const unsigned char *>(plain.constData()),
                                               plain.size(), p, h, nullptr, p + h - kNonce, key_);

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
