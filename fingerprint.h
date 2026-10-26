#pragma once
#include <QByteArray>
#include <QObject>
#include <QString>

// After a password unlock the vault key K goes into the kernel user keyring, so a fingerprint
// can open the vault again without the password, like a phone. The keyring lives in kernel
// memory (never swapped) and dies with the user's last session, so a reboot or logout asks
// for the password again. Any process running as this user can read it, the same reach a
// keylogger on X11 already has; README explains the trade-off.
namespace quickKey {
bool store(const QByteArray &key);
bool exists();
QByteArray load(); // the caller wipes it
void forget();
}

// fprintd over the system bus. The reader is claimed only between start() and stop(), so the
// GNOME lock screen and other apps can use it the rest of the time.
class Fingerprint : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
    bool enrolled(); // a reader exists and the current user has at least one finger
    bool start();
    void stop();

signals:
    void matched();
    void noMatch();     // scanning continues
    void unavailable(); // reader unplugged or failing; scanning stopped

private slots:
    void onVerifyStatus(const QString &result, bool done);

private:
    QString device_;
    bool active_ = false;
};
