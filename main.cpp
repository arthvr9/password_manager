#include "vault.h"
#include <QtDBus>
#include <QtWidgets>
#include <sodium.h>
#include <sys/prctl.h>

static constexpr int kAutoLockMs = 5 * 60 * 1000;

struct Entry {
    QString id, title, user, pass, url, notes, category;
};

static const char *kStyle = R"(
* { font-size: 10pt; }
QWidget { background: #141518; color: #e3e4e6; }
QMainWindow, QDialog { background: #141518; }
QLabel { background: transparent; }
QLabel#h1 { font-size: 17pt; font-weight: 600; }
QLabel#muted, QLabel#field { color: #8a8d93; }
QLabel#field { font-size: 8.5pt; font-weight: 600; margin-top: 10px; }
QLabel#error { color: #e5736f; }
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background: #1b1c20; border: 1px solid #2b2d32; border-radius: 4px; padding: 7px 9px;
    selection-background-color: #3d5a99;
}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #6b93e6; }
QLineEdit#search { background: #18191c; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: #1b1c20; border: 1px solid #2b2d32; selection-background-color: #262a33; }
QPushButton {
    background: #212328; border: 1px solid #2c2f35; border-radius: 4px; padding: 7px 14px;
}
QPushButton:hover { background: #282b31; }
QPushButton:pressed { background: #1c1e22; }
QPushButton:disabled { color: #5b5e64; }
QPushButton#primary { background: #6b93e6; border-color: #6b93e6; color: #0d0e10; font-weight: 600; }
QPushButton#primary:hover { background: #7da1ea; }
QPushButton#danger { background: transparent; border-color: transparent; color: #e5736f; }
QPushButton#danger:hover { background: #2a1d1d; }
QPushButton#flat { background: transparent; border-color: transparent; color: #a9acb2; }
QPushButton#flat:hover { background: #212328; color: #e3e4e6; }
QListWidget { border: none; outline: 0; }
QListWidget#sidebar { background: #101114; }
QListWidget#sidebar::item { padding: 7px 14px; color: #a9acb2; background: transparent; border: none; }
QListWidget#sidebar::item:hover { background: #16171b; }
QListWidget#sidebar::item:selected { background: #1b1d22; color: #e3e4e6; }
QListWidget#entries::item:selected { background: #1d2027; }
QWidget#sidebarPane { background: #101114; }
QFrame#vline { background: #24262b; }
QCheckBox { background: transparent; spacing: 10px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #3a3d44; border-radius: 3px; background: #1b1c20; }
QCheckBox::indicator:checked { background: #6b93e6; border-color: #6b93e6; }
QCheckBox::indicator:hover { border-color: #6b93e6; }
QStatusBar { background: #101114; color: #8a8d93; border-top: 1px solid #24262b; padding-left: 10px; }
QStatusBar::item { border: none; }
QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #2c2f35; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: #1b1c20; color: #e3e4e6; border: 1px solid #2b2d32; }
QMessageBox QLabel { min-width: 280px; }
)";

static QLabel *label(const QString &text, const char *name)
{
    auto *l = new QLabel(text);
    l->setObjectName(name);
    return l;
}

static QPushButton *button(const QString &text, const char *name = nullptr)
{
    auto *b = new QPushButton(text);
    if (name) b->setObjectName(name);
    b->setCursor(Qt::PointingHandCursor);
    return b;
}

static QFrame *vline()
{
    auto *f = new QFrame;
    f->setObjectName("vline");
    f->setFixedWidth(1);
    return f;
}

// Entry rows: title on top, username muted below.
class EntryDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    QSize sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const override { return {0, 54}; }
    void paint(QPainter *p, const QStyleOptionViewItem &opt, const QModelIndex &idx) const override
    {
        p->save();
        const bool sel = opt.state.testFlag(QStyle::State_Selected);
        const bool hover = opt.state.testFlag(QStyle::State_MouseOver);
        if (sel || hover) p->fillRect(opt.rect, sel ? QColor("#1d2027") : QColor("#17181b"));
        if (sel) p->fillRect(QRect(opt.rect.left(), opt.rect.top(), 2, opt.rect.height()), QColor("#6b93e6"));
        const QRect r = opt.rect.adjusted(16, 9, -12, -9);
        QFont f = opt.font;
        f.setWeight(QFont::DemiBold);
        p->setFont(f);
        p->setPen(QColor("#e3e4e6"));
        const QString title = idx.data(Qt::DisplayRole).toString();
        p->drawText(r, Qt::AlignLeft | Qt::AlignTop,
                    QFontMetrics(f).elidedText(title.isEmpty() ? "(sem título)" : title, Qt::ElideRight, r.width()));
        f.setWeight(QFont::Normal);
        f.setPointSizeF(f.pointSizeF() * 0.9);
        p->setFont(f);
        p->setPen(QColor("#8a8d93"));
        p->drawText(r, Qt::AlignLeft | Qt::AlignBottom,
                    QFontMetrics(f).elidedText(idx.data(Qt::UserRole + 1).toString(), Qt::ElideRight, r.width()));
        p->restore();
    }
};

class GeneratorDialog : public QDialog {
public:
    explicit GeneratorDialog(QWidget *parent) : QDialog(parent)
    {
        setWindowTitle("Gerar senha");
        setMinimumWidth(420);
        auto *lay = new QVBoxLayout(this);
        lay->setContentsMargins(20, 20, 20, 20);
        lay->setSpacing(10);

        preview_ = new QLineEdit;
        preview_->setReadOnly(true);
        preview_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        auto *regen = button("Gerar outra");
        auto *row = new QHBoxLayout;
        row->addWidget(preview_, 1);
        row->addWidget(regen);
        lay->addLayout(row);

        length_ = new QSpinBox;
        length_->setRange(8, 128);
        length_->setValue(20);
        auto *lenRow = new QHBoxLayout;
        lenRow->addWidget(label("Tamanho", "muted"));
        lenRow->addStretch();
        lenRow->addWidget(length_);
        lay->addLayout(lenRow);

        for (const char *t : {"Maiúsculas (A-Z)", "Minúsculas (a-z)", "Números (2-9)", "Símbolos (!@#$...)"}) {
            auto *c = new QCheckBox(t);
            c->setChecked(true);
            connect(c, &QCheckBox::toggled, this, &GeneratorDialog::regenerate);
            checks_ << c;
            lay->addWidget(c);
        }
        lay->addWidget(label("Caracteres ambíguos (0 O 1 l I) ficam de fora.", "muted"));

        auto *cancel = button("Cancelar");
        use_ = button("Usar senha", "primary");
        auto *btns = new QHBoxLayout;
        btns->addStretch();
        btns->addWidget(cancel);
        btns->addWidget(use_);
        lay->addSpacing(8);
        lay->addLayout(btns);

        connect(regen, &QPushButton::clicked, this, &GeneratorDialog::regenerate);
        connect(length_, &QSpinBox::valueChanged, this, &GeneratorDialog::regenerate);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(use_, &QPushButton::clicked, this, &QDialog::accept);
        use_->setDefault(true);
        regenerate();
    }
    QString password() const { return preview_->text(); }

private:
    void regenerate()
    {
        preview_->setText(generatePassword(length_->value(), checks_[0]->isChecked(), checks_[1]->isChecked(),
                                           checks_[2]->isChecked(), checks_[3]->isChecked()));
        use_->setEnabled(!preview_->text().isEmpty());
    }
    QLineEdit *preview_;
    QSpinBox *length_;
    QList<QCheckBox *> checks_;
    QPushButton *use_;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow()
        : vault_(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/vault.bin")
    {
        setWindowTitle("Pass Manager");
        resize(1100, 680);
        stack_ = new QStackedWidget;
        stack_->addWidget(buildUnlock());
        stack_->addWidget(buildMain());
        setCentralWidget(stack_);
        statusBar()->setSizeGripEnabled(false);
        statusBar()->hide();

        saveTimer_.setSingleShot(true);
        saveTimer_.setInterval(400);
        connect(&saveTimer_, &QTimer::timeout, this, &MainWindow::persist);

        idleTimer_.setSingleShot(true);
        idleTimer_.setInterval(kAutoLockMs);
        connect(&idleTimer_, &QTimer::timeout, this, &MainWindow::lock);
        qApp->installEventFilter(this);

        // lock when the session screen locks (GNOME and freedesktop names)
        auto bus = QDBusConnection::sessionBus();
        bus.connect("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver",
                    "ActiveChanged", this, SLOT(onScreenSaver(bool)));
        bus.connect("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver",
                    "ActiveChanged", this, SLOT(onScreenSaver(bool)));

        auto sc = [this](QKeySequence k, auto fn) {
            connect(new QShortcut(k, this), &QShortcut::activated, this, [this, fn] {
                if (vault_.isOpen()) fn();
            });
        };
        sc(QKeySequence::New, [this] { newEntry(); });
        sc(QKeySequence::Find, [this] { search_->setFocus(); search_->selectAll(); });
        sc(QKeySequence("Ctrl+L"), [this] { lock(); });
        sc(QKeySequence("Ctrl+Shift+C"), [this] { if (!currentId_.isEmpty()) copy(pass_->text(), "Senha copiada"); });
        sc(QKeySequence("Ctrl+B"), [this] { if (!currentId_.isEmpty()) copy(user_->text(), "Usuário copiado"); });

        showUnlock();
    }

protected:
    bool eventFilter(QObject *o, QEvent *e) override
    {
        switch (e->type()) {
        case QEvent::KeyPress:
        case QEvent::MouseButtonPress:
        case QEvent::MouseMove:
        case QEvent::Wheel:
            if (vault_.isOpen()) idleTimer_.start();
            break;
        default:
            break;
        }
        return QMainWindow::eventFilter(o, e);
    }

    void closeEvent(QCloseEvent *e) override
    {
        if (saveTimer_.isActive()) persist();
        e->accept();
    }

private slots:
    void onScreenSaver(bool active)
    {
        if (active) lock();
    }

private:
    // ---------- unlock page ----------
    QWidget *buildUnlock()
    {
        auto *page = new QWidget;
        auto *col = new QWidget;
        col->setFixedWidth(340);
        auto *lay = new QVBoxLayout(col);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->setSpacing(10);

        unlockTitle_ = label("", "h1");
        unlockHint_ = label("", "muted");
        unlockHint_->setWordWrap(true);
        master_ = new QLineEdit;
        master_->setEchoMode(QLineEdit::Password);
        master_->setPlaceholderText("Senha mestra");
        confirm_ = new QLineEdit;
        confirm_->setEchoMode(QLineEdit::Password);
        confirm_->setPlaceholderText("Confirme a senha mestra");
        unlockError_ = label("", "error");
        unlockError_->setWordWrap(true);
        unlockBtn_ = button("", "primary");

        lay->addWidget(unlockTitle_);
        lay->addWidget(unlockHint_);
        lay->addSpacing(12);
        lay->addWidget(master_);
        lay->addWidget(confirm_);
        lay->addWidget(unlockError_);
        lay->addWidget(unlockBtn_);

        auto *outer = new QGridLayout(page);
        outer->addWidget(col, 0, 0, Qt::AlignCenter);

        connect(unlockBtn_, &QPushButton::clicked, this, &MainWindow::unlock);
        connect(master_, &QLineEdit::returnPressed, this, [this] {
            confirm_->isVisible() ? confirm_->setFocus() : unlock();
        });
        connect(confirm_, &QLineEdit::returnPressed, this, &MainWindow::unlock);
        return page;
    }

    void showUnlock()
    {
        const bool first = !vault_.exists();
        unlockTitle_->setText(first ? "Criar cofre" : "Cofre bloqueado");
        unlockHint_->setText(first ? "Defina a senha mestra. Ela não pode ser recuperada: se esquecer, "
                                     "as senhas guardadas são perdidas."
                                   : "Digite a senha mestra para desbloquear.");
        unlockBtn_->setText(first ? "Criar cofre" : "Desbloquear");
        confirm_->setVisible(first);
        master_->clear();
        confirm_->clear();
        unlockError_->clear();
        unlockError_->hide();
        statusBar()->hide();
        stack_->setCurrentIndex(0);
        master_->setFocus();
    }

    void unlock()
    {
        const bool first = !vault_.exists();
        auto fail = [this](const QString &msg) {
            unlockError_->setText(msg);
            unlockError_->show();
            master_->selectAll();
            master_->setFocus();
        };
        if (master_->text().isEmpty()) return;
        if (first && master_->text().size() < 8) return fail("Use pelo menos 8 caracteres.");
        if (first && master_->text() != confirm_->text()) return fail("As senhas não conferem.");

        unlockBtn_->setEnabled(false);
        unlockBtn_->setText(first ? "Criando..." : "Desbloqueando...");
        QApplication::setOverrideCursor(Qt::WaitCursor);
        QApplication::processEvents(); // Argon2id takes ~1s; let the label repaint first

        QByteArray plain;
        const bool ok = first ? vault_.create(master_->text().toUtf8()) : vault_.open(master_->text().toUtf8(), plain);
        master_->clear();
        confirm_->clear();
        QApplication::restoreOverrideCursor();
        unlockBtn_->setEnabled(true);

        if (!ok) {
            showUnlock();
            return fail(vault_.error);
        }
        load(plain);
        sodium_memzero(plain.data(), plain.size());

        currentId_.clear();
        search_->clear();
        refreshSidebar();
        sidebar_->setCurrentRow(0);
        stack_->setCurrentIndex(1);
        statusBar()->show();
        idleTimer_.start();
        search_->setFocus();
    }

    void lock()
    {
        if (!vault_.isOpen()) return;
        if (saveTimer_.isActive()) persist();
        idleTimer_.stop();
        vault_.close();
        // ponytail: QString contents can't be reliably wiped; dropping them is best effort
        entries_.clear();
        currentId_.clear();
        list_->clear();
        sidebar_->clear();
        clearForm();
        showUnlock();
    }

    void load(const QByteArray &plain)
    {
        entries_.clear();
        const QJsonArray arr = QJsonDocument::fromJson(plain).object().value("entries").toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            entries_.push_back({o["id"].toString(), o["title"].toString(), o["user"].toString(), o["pass"].toString(),
                                o["url"].toString(), o["notes"].toString(), o["category"].toString()});
        }
    }

    void persist()
    {
        saveTimer_.stop();
        QJsonArray arr;
        for (const Entry &e : entries_)
            arr.append(QJsonObject{{"id", e.id}, {"title", e.title}, {"user", e.user}, {"pass", e.pass},
                                   {"url", e.url}, {"notes", e.notes}, {"category", e.category}});
        QByteArray plain = QJsonDocument(QJsonObject{{"entries", arr}}).toJson(QJsonDocument::Compact);
        const bool ok = vault_.save(plain);
        sodium_memzero(plain.data(), plain.size());
        if (ok)
            statusBar()->showMessage("Salvo", 2000);
        else
            QMessageBox::critical(this, "Erro ao salvar", vault_.error);
    }

    // ---------- main page ----------
    QWidget *buildMain()
    {
        // sidebar
        auto *sidePane = new QWidget;
        sidePane->setObjectName("sidebarPane");
        sidePane->setFixedWidth(210);
        auto *sideLay = new QVBoxLayout(sidePane);
        sideLay->setContentsMargins(0, 16, 0, 12);
        sideLay->setSpacing(6);
        auto *catLabel = label("CATEGORIAS", "field");
        catLabel->setContentsMargins(14, 0, 0, 0);
        sidebar_ = new QListWidget;
        sidebar_->setObjectName("sidebar");
        auto *lockBtn = button("Bloquear  (Ctrl+L)", "flat");
        sideLay->addWidget(catLabel);
        sideLay->addWidget(sidebar_, 1);
        auto *lockRow = new QHBoxLayout;
        lockRow->setContentsMargins(8, 0, 8, 0);
        lockRow->addWidget(lockBtn);
        sideLay->addLayout(lockRow);

        // entry list
        auto *listPane = new QWidget;
        listPane->setFixedWidth(320);
        auto *listLay = new QVBoxLayout(listPane);
        listLay->setContentsMargins(0, 12, 0, 0);
        listLay->setSpacing(10);
        search_ = new QLineEdit;
        search_->setObjectName("search");
        search_->setPlaceholderText("Buscar  (Ctrl+F)");
        search_->setClearButtonEnabled(true);
        auto *newBtn = button("Nova", "primary");
        newBtn->setToolTip("Nova entrada (Ctrl+N)");
        auto *top = new QHBoxLayout;
        top->setContentsMargins(12, 0, 12, 0);
        top->addWidget(search_, 1);
        top->addWidget(newBtn);
        list_ = new QListWidget;
        list_->setObjectName("entries");
        list_->setItemDelegate(new EntryDelegate(list_));
        list_->setMouseTracking(true);
        listLay->addLayout(top);
        listLay->addWidget(list_, 1);

        // detail
        detail_ = new QStackedWidget;
        auto *empty = label("Selecione uma entrada ou crie uma nova com Ctrl+N.", "muted");
        empty->setAlignment(Qt::AlignCenter);
        detail_->addWidget(empty);
        detail_->addWidget(buildForm());

        auto *page = new QWidget;
        auto *lay = new QHBoxLayout(page);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->setSpacing(0);
        lay->addWidget(sidePane);
        lay->addWidget(vline());
        lay->addWidget(listPane);
        lay->addWidget(vline());
        lay->addWidget(detail_, 1);

        connect(lockBtn, &QPushButton::clicked, this, &MainWindow::lock);
        connect(newBtn, &QPushButton::clicked, this, &MainWindow::newEntry);
        connect(search_, &QLineEdit::textChanged, this, &MainWindow::refreshList);
        connect(sidebar_, &QListWidget::currentRowChanged, this, &MainWindow::refreshList);
        connect(list_, &QListWidget::currentItemChanged, this, [this](QListWidgetItem *it) {
            showEntry(it ? it->data(Qt::UserRole).toString() : QString());
        });
        connect(search_, &QLineEdit::returnPressed, this, [this] {
            if (list_->count()) {
                list_->setCurrentRow(0);
                list_->setFocus();
            }
        });
        return page;
    }

    QWidget *buildForm()
    {
        auto *form = new QWidget;
        auto *lay = new QVBoxLayout(form);
        lay->setContentsMargins(32, 20, 32, 16);
        lay->setSpacing(4);

        title_ = new QLineEdit;
        title_->setPlaceholderText("Título");
        title_->setStyleSheet("QLineEdit { font-size: 15pt; font-weight: 600; border-color: transparent;"
                              " background: transparent; padding-left: 0; }"
                              "QLineEdit:focus { border-color: #2b2d32; background: #1b1c20; padding-left: 9px; }");
        lay->addWidget(title_);

        category_ = new QComboBox;
        category_->setEditable(true);
        category_->setInsertPolicy(QComboBox::NoInsert);
        category_->lineEdit()->setPlaceholderText("Sem categoria");
        lay->addWidget(label("CATEGORIA", "field"));
        lay->addWidget(category_);

        user_ = new QLineEdit;
        auto *copyUser = button("Copiar");
        copyUser->setToolTip("Ctrl+B");
        lay->addWidget(label("USUÁRIO", "field"));
        lay->addLayout(row({user_, copyUser}));

        pass_ = new QLineEdit;
        pass_->setEchoMode(QLineEdit::Password);
        pass_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        reveal_ = button("Mostrar");
        auto *gen = button("Gerar");
        auto *copyPass = button("Copiar");
        copyPass->setToolTip("Ctrl+Shift+C");
        lay->addWidget(label("SENHA", "field"));
        lay->addLayout(row({pass_, reveal_, gen, copyPass}));

        url_ = new QLineEdit;
        url_->setPlaceholderText("https://");
        auto *openUrl = button("Abrir");
        lay->addWidget(label("URL", "field"));
        lay->addLayout(row({url_, openUrl}));

        notes_ = new QPlainTextEdit;
        lay->addWidget(label("NOTAS", "field"));
        lay->addWidget(notes_, 1);

        auto *del = button("Excluir entrada", "danger");
        auto *foot = new QHBoxLayout;
        foot->setContentsMargins(0, 10, 0, 0);
        foot->addStretch();
        foot->addWidget(del);
        lay->addLayout(foot);

        for (QLineEdit *e : {title_, user_, pass_, url_})
            connect(e, &QLineEdit::textEdited, this, &MainWindow::commit);
        connect(notes_, &QPlainTextEdit::textChanged, this, &MainWindow::commit);
        connect(category_, &QComboBox::currentTextChanged, this, &MainWindow::commit);
        connect(category_->lineEdit(), &QLineEdit::editingFinished, this, &MainWindow::refreshSidebar);
        connect(category_, &QComboBox::activated, this, &MainWindow::refreshSidebar);

        connect(copyUser, &QPushButton::clicked, this, [this] { copy(user_->text(), "Usuário copiado"); });
        connect(copyPass, &QPushButton::clicked, this, [this] { copy(pass_->text(), "Senha copiada"); });
        connect(reveal_, &QPushButton::clicked, this, [this] { setRevealed(pass_->echoMode() == QLineEdit::Password); });
        connect(gen, &QPushButton::clicked, this, [this] {
            GeneratorDialog d(this);
            if (d.exec() != QDialog::Accepted) return;
            pass_->setText(d.password());
            commit();
        });
        connect(openUrl, &QPushButton::clicked, this, [this] {
            if (!url_->text().trimmed().isEmpty()) QDesktopServices::openUrl(QUrl::fromUserInput(url_->text().trimmed()));
        });
        connect(del, &QPushButton::clicked, this, &MainWindow::deleteEntry);
        return form;
    }

    static QHBoxLayout *row(std::initializer_list<QWidget *> ws)
    {
        auto *r = new QHBoxLayout;
        r->setSpacing(6);
        bool first = true;
        for (QWidget *w : ws) {
            r->addWidget(w, first ? 1 : 0);
            first = false;
        }
        return r;
    }

    void setRevealed(bool on)
    {
        pass_->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
        reveal_->setText(on ? "Ocultar" : "Mostrar");
    }

    Entry *find(const QString &id)
    {
        for (Entry &e : entries_)
            if (e.id == id) return &e;
        return nullptr;
    }

    QStringList categories() const
    {
        QStringList c;
        for (const Entry &e : entries_)
            if (!e.category.isEmpty() && !c.contains(e.category)) c << e.category;
        std::sort(c.begin(), c.end(), [](const QString &a, const QString &b) { return a.localeAwareCompare(b) < 0; });
        return c;
    }

    // Row 0 = all, then categories, then "uncategorized" if any. Category name kept in UserRole.
    void refreshSidebar()
    {
        if (!vault_.isOpen()) return;
        const QString keep = sidebar_->currentItem() ? sidebar_->currentItem()->data(Qt::UserRole).toString() : "*";
        const QSignalBlocker block(sidebar_);
        sidebar_->clear();
        auto add = [this](const QString &text, const QString &key, int n) {
            auto *it = new QListWidgetItem(QString("%1   %2").arg(text).arg(n));
            it->setData(Qt::UserRole, key);
            sidebar_->addItem(it);
            return it;
        };
        add("Todas", "*", entries_.size());
        for (const QString &c : categories())
            add(c, c, std::count_if(entries_.begin(), entries_.end(), [&](const Entry &e) { return e.category == c; }));
        const int none = std::count_if(entries_.begin(), entries_.end(), [](const Entry &e) { return e.category.isEmpty(); });
        if (none && none != int(entries_.size())) add("Sem categoria", "", none);

        sidebar_->setCurrentRow(0);
        for (int i = 0; i < sidebar_->count(); ++i)
            if (sidebar_->item(i)->data(Qt::UserRole).toString() == keep) sidebar_->setCurrentRow(i);

        const QSignalBlocker blockCat(category_);
        const QString cur = category_->currentText();
        category_->clear();
        category_->addItems(categories());
        category_->setCurrentText(cur);
        refreshList();
    }

    void refreshList()
    {
        if (!vault_.isOpen()) return;
        const QString cat = sidebar_->currentItem() ? sidebar_->currentItem()->data(Qt::UserRole).toString() : "*";
        const QString q = search_->text().trimmed();
        std::vector<const Entry *> shown;
        for (const Entry &e : entries_) {
            if (cat != "*" && e.category != cat) continue;
            if (!q.isEmpty() && !e.title.contains(q, Qt::CaseInsensitive) && !e.user.contains(q, Qt::CaseInsensitive) &&
                !e.url.contains(q, Qt::CaseInsensitive) && !e.category.contains(q, Qt::CaseInsensitive))
                continue;
            shown.push_back(&e);
        }
        std::sort(shown.begin(), shown.end(),
                  [](const Entry *a, const Entry *b) { return a->title.localeAwareCompare(b->title) < 0; });

        const QString keep = currentId_;
        {
            const QSignalBlocker block(list_);
            list_->clear();
            for (const Entry *e : shown) {
                auto *it = new QListWidgetItem(e->title);
                it->setData(Qt::UserRole, e->id);
                it->setData(Qt::UserRole + 1, e->user);
                list_->addItem(it);
                if (e->id == keep) list_->setCurrentItem(it);
            }
        }
        showEntry(list_->currentItem() ? keep : QString());
    }

    void clearForm()
    {
        loading_ = true;
        for (QLineEdit *e : {title_, user_, pass_, url_}) e->clear();
        notes_->clear();
        category_->setCurrentText("");
        loading_ = false;
        setRevealed(false);
        detail_->setCurrentIndex(0);
    }

    void showEntry(const QString &id)
    {
        const Entry *e = find(id);
        if (!e) {
            currentId_.clear();
            clearForm();
            return;
        }
        if (id == currentId_ && detail_->currentIndex() == 1) return;
        currentId_ = id;
        loading_ = true;
        title_->setText(e->title);
        category_->setCurrentText(e->category);
        user_->setText(e->user);
        pass_->setText(e->pass);
        url_->setText(e->url);
        notes_->setPlainText(e->notes);
        loading_ = false;
        setRevealed(false);
        detail_->setCurrentIndex(1);
    }

    // Any edit goes straight to memory; disk write is debounced.
    void commit()
    {
        if (loading_) return;
        Entry *e = find(currentId_);
        if (!e) return;
        e->title = title_->text();
        e->category = category_->currentText().trimmed();
        e->user = user_->text();
        e->pass = pass_->text();
        e->url = url_->text().trimmed();
        e->notes = notes_->toPlainText();
        if (auto *it = list_->currentItem()) {
            it->setText(e->title);
            it->setData(Qt::UserRole + 1, e->user);
        }
        saveTimer_.start();
    }

    void newEntry()
    {
        const QString cat = sidebar_->currentItem() ? sidebar_->currentItem()->data(Qt::UserRole).toString() : "*";
        Entry e;
        e.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        e.category = cat == "*" ? QString() : cat;
        entries_.push_back(e);
        clearForm(); // so showEntry reloads the form for the new id
        currentId_ = e.id;
        search_->clear();
        refreshSidebar();
        persist();
        title_->setFocus();
    }

    void deleteEntry()
    {
        const Entry *e = find(currentId_);
        if (!e) return;
        const QString name = e->title.isEmpty() ? "(sem título)" : e->title;
        if (QMessageBox::question(this, "Excluir entrada", QString("Excluir \"%1\"? Não dá para desfazer.").arg(name)) !=
            QMessageBox::Yes)
            return;
        entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const Entry &x) { return x.id == currentId_; }),
                       entries_.end());
        currentId_.clear();
        refreshSidebar();
        persist();
    }

    void copy(const QString &text, const QString &msg)
    {
        if (text.isEmpty()) return;
        auto *md = new QMimeData;
        md->setText(text);
        md->setData("x-kde-passwordManagerHint", "secret"); // clipboard managers that honor it skip history
        QApplication::clipboard()->setMimeData(md);
        statusBar()->showMessage(msg, 2500);
    }

    Vault vault_;
    std::vector<Entry> entries_;
    QString currentId_;
    bool loading_ = false;
    QTimer saveTimer_, idleTimer_;

    QStackedWidget *stack_, *detail_;
    QLabel *unlockTitle_, *unlockHint_, *unlockError_;
    QLineEdit *master_, *confirm_;
    QPushButton *unlockBtn_, *reveal_;
    QListWidget *sidebar_, *list_;
    QLineEdit *search_, *title_, *user_, *pass_, *url_;
    QComboBox *category_;
    QPlainTextEdit *notes_;
};

int main(int argc, char **argv)
{
    prctl(PR_SET_DUMPABLE, 0); // no core dumps, no ptrace from other same-user processes
    if (sodium_init() < 0) return 1;

    QApplication app(argc, argv);
    app.setApplicationName("pass-manager");
    app.setApplicationDisplayName("Pass Manager");
    app.setDesktopFileName("pass-manager");
    app.setWindowIcon(QIcon::fromTheme("dialog-password"));
    app.setStyle("Fusion");

    QPalette pal;
    pal.setColor(QPalette::Window, QColor("#141518"));
    pal.setColor(QPalette::WindowText, QColor("#e3e4e6"));
    pal.setColor(QPalette::Base, QColor("#1b1c20"));
    pal.setColor(QPalette::AlternateBase, QColor("#17181b"));
    pal.setColor(QPalette::Text, QColor("#e3e4e6"));
    pal.setColor(QPalette::Button, QColor("#212328"));
    pal.setColor(QPalette::ButtonText, QColor("#e3e4e6"));
    pal.setColor(QPalette::Highlight, QColor("#3d5a99"));
    pal.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    pal.setColor(QPalette::PlaceholderText, QColor("#5f6268"));
    pal.setColor(QPalette::ToolTipBase, QColor("#1b1c20"));
    pal.setColor(QPalette::ToolTipText, QColor("#e3e4e6"));
    app.setPalette(pal);
    app.setStyleSheet(kStyle);

    MainWindow w;
    w.show();
    return app.exec();
}

#include "main.moc"
