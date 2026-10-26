#include "fingerprint.h"
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// ---------- kernel user keyring ----------

static const char *kKeyName = "pass-manager:vault";

static long findKey()
{
    return syscall(SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, "user", kKeyName, 0);
}

bool quickKey::store(const QByteArray &key)
{
    return syscall(SYS_add_key, "user", kKeyName, key.constData(), size_t(key.size()), KEY_SPEC_USER_KEYRING) >= 0;
}

bool quickKey::exists() { return findKey() >= 0; }

QByteArray quickKey::load()
{
    const long id = findKey();
    if (id < 0) return {};
    QByteArray key(64, '\0');
    const long n = syscall(SYS_keyctl, KEYCTL_READ, id, key.data(), key.size());
    if (n <= 0 || n > key.size()) return {};
    key.truncate(n);
    return key;
}

void quickKey::forget()
{
    const long id = findKey();
    if (id >= 0) syscall(SYS_keyctl, KEYCTL_INVALIDATE, id); // also wipes the payload
}

// ---------- fprintd ----------

static const char *kService = "net.reactivated.Fprint";
static const char *kDevice = "net.reactivated.Fprint.Device";

static QDBusMessage call(const QString &path, const QString &iface, const QString &method,
                         const QVariantList &args = {})
{
    auto msg = QDBusMessage::createMethodCall(kService, path, iface, method);
    msg.setArguments(args);
    return QDBusConnection::systemBus().call(msg, QDBus::Block, 5000);
}

static bool ok(const QDBusMessage &reply) { return reply.type() == QDBusMessage::ReplyMessage; }

bool Fingerprint::enrolled()
{
    const QDBusMessage dev = call("/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager", "GetDefaultDevice");
    if (!ok(dev)) return false; // fprintd not installed, or no reader
    device_ = dev.arguments().value(0).value<QDBusObjectPath>().path();
    // empty username = the caller; fails with NoEnrolledPrints when there are none
    const QDBusMessage fingers = call(device_, kDevice, "ListEnrolledFingers", {QString()});
    return ok(fingers) && !fingers.arguments().value(0).toStringList().isEmpty();
}

bool Fingerprint::start()
{
    if (active_) return true;
    if (device_.isEmpty() && !enrolled()) return false;
    if (!ok(call(device_, kDevice, "Claim", {QString()}))) return false; // e.g. in use by the lock screen
    QDBusConnection::systemBus().connect(kService, device_, kDevice, "VerifyStatus", this,
                                         SLOT(onVerifyStatus(QString, bool)));
    if (!ok(call(device_, kDevice, "VerifyStart", {QString("any")}))) {
        QDBusConnection::systemBus().disconnect(kService, device_, kDevice, "VerifyStatus", this,
                                                SLOT(onVerifyStatus(QString, bool)));
        call(device_, kDevice, "Release");
        return false;
    }
    active_ = true;
    return true;
}

void Fingerprint::stop()
{
    if (!active_) return;
    active_ = false;
    QDBusConnection::systemBus().disconnect(kService, device_, kDevice, "VerifyStatus", this,
                                            SLOT(onVerifyStatus(QString, bool)));
    call(device_, kDevice, "VerifyStop");
    call(device_, kDevice, "Release");
}

void Fingerprint::onVerifyStatus(const QString &result, bool done)
{
    if (!active_) return;
    if (result == "verify-match") {
        stop();
        emit matched();
        return;
    }
    if (result == "verify-disconnected" || result == "verify-unknown-error") {
        stop();
        emit unavailable();
        return;
    }
    if (result == "verify-no-match") emit noMatch(); // the handler may stop() us
    // "retry" results (finger too short, not centered) keep the same attempt going;
    // a finished attempt needs a new VerifyStart for the next touch
    if (done && active_ && (!ok(call(device_, kDevice, "VerifyStop")) ||
                            !ok(call(device_, kDevice, "VerifyStart", {QString("any")})))) {
        stop();
        emit unavailable();
    }
}
