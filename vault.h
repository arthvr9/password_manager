#pragma once
#include <QByteArray>
#include <QString>

// Encrypted file: "PMV1" | salt(16) | opslimit(u64) | memlimit(u64) | nonce(24) | ciphertext+tag
// Key = Argon2id(password, salt), cipher = XChaCha20-Poly1305, header authenticated as AAD.
class Vault {
public:
    explicit Vault(QString path);
    ~Vault();

    bool exists() const;
    bool isOpen() const { return key_ != nullptr; }
    bool create(QByteArray password);                 // new salt + key, writes empty payload
    bool open(QByteArray password, QByteArray &plain); // false on wrong password or tampered file
    bool save(const QByteArray &plain);
    void close();                                      // wipes the key

    QString error;

private:
    bool derive(QByteArray &password);
    QString path_;
    unsigned char *key_ = nullptr; // sodium_malloc'd, mlocked, guarded
    unsigned char salt_[16];
    quint64 ops_ = 0, mem_ = 0;
};

QString generatePassword(int length, bool upper, bool lower, bool digits, bool symbols);
