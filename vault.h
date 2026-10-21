#pragma once
#include <QByteArray>
#include <QString>

// The data is encrypted with a random data key K (XChaCha20-Poly1305, whole header as AAD).
// K is stored wrapped twice, like LUKS key slots:
//   password slot: KEK = BLAKE2b(key = Argon2id(password), msg = TPM secret)
//   recovery slot: KEK = BLAKE2b(key = recovery key, msg = salt)
// The TPM secret is sealed by systemd-creds (tpm2+host, user scoped, no PCRs), so a copied
// vault file can't be brute-forced off this machine. Only when the machine has no TPM at all
// does the slot use the password alone; a TPM that is present but fails is an error.
// ponytail: the TPM secret passes through QProcess pipe buffers that are freed without wiping.
//
// v2 file: "PMV2" | pw salt(16) | opslimit(u64) | memlimit(u64) | cred len(u32) | cred
//          | pw slot(72) | rec salt(16) | rec slot(72) | data nonce(24) | ciphertext+tag
class Vault {
public:
    // `credsBin` empty disables the TPM; tests point it at a failing binary
    explicit Vault(QString path, QString credsBin = "/usr/bin/systemd-creds");
    ~Vault();

    bool exists() const;
    bool isOpen() const { return key_ != nullptr; }
    bool usesTpm() const { return !cred_.isEmpty(); }

    // create() and a v1 upgrade inside open() fill `recovery`; show it to the user once.
    bool create(QByteArray password, QString &recovery);
    bool open(QByteArray password, QByteArray &plain, QString &recovery);
    bool openWithRecovery(const QString &recovery, QByteArray &plain);
    bool verifyPassword(QByteArray password);
    // re-wraps K under a new password and TPM secret and saves `plain`; on failure nothing changes
    bool setPassword(QByteArray password, const QByteArray &plain);
    // verifies the password, replaces the recovery slot and saves; the old key stops working
    bool resetRecovery(QByteArray password, const QByteArray &plain, QString &recovery);
    bool save(const QByteArray &plain);
    void close(); // wipes K

    QString error;

private:
    bool read(QByteArray &data);
    int parse(const QByteArray &data); // header length, 0 on error
    bool passwordKek(QByteArray &password, unsigned char *kek);
    void newRecovery(QString &recovery);
    bool tpmPresent() const;
    bool decryptData(const QByteArray &data, int headerLen, QByteArray &plain);
    bool openV1(const QByteArray &data, QByteArray &password, QByteArray &plain, QString &recovery);

    QString path_;
    QString creds_;
    unsigned char *key_ = nullptr; // sodium_malloc'd, mlocked, guarded
    unsigned char pwSalt_[16], recSalt_[16];
    unsigned char pwSlot_[72], recSlot_[72];
    quint64 ops_ = 0, mem_ = 0;
    QByteArray cred_;
};

QString generatePassword(int length, bool upper, bool lower, bool digits, bool symbols);
