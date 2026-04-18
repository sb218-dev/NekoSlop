#include "dialog_app_selector.h"

#include <QSettings>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QDir>
#include <QListWidgetItem>
#include <QApplication>
#include <QStyle>
#include <QSortFilterProxyModel>
#include <algorithm>

DialogAppSelector::DialogAppSelector(const QStringList &alreadySelected, QWidget *parent)
    : QDialog(parent) {
    setWindowTitle(tr("Выбор приложений для проксирования"));
    setMinimumSize(620, 560);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

    // --- Apply dark stylesheet ---
    setStyleSheet(R"(
        QDialog {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }
        QLineEdit {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 6px;
            padding: 6px 10px;
            color: #cdd6f4;
            font-size: 13px;
        }
        QLineEdit:focus {
            border: 1px solid #89b4fa;
        }
        QListWidget {
            background-color: #181825;
            border: 1px solid #313244;
            border-radius: 8px;
            outline: none;
            padding: 4px;
        }
        QListWidget::item {
            padding: 7px 10px;
            border-radius: 5px;
            color: #cdd6f4;
        }
        QListWidget::item:hover {
            background-color: #313244;
        }
        QListWidget::item:selected {
            background-color: #45475a;
        }
        QScrollBar:vertical {
            background: #181825;
            width: 8px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #585b70;
            border-radius: 4px;
        }
        QPushButton {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 6px;
            padding: 6px 18px;
            color: #cdd6f4;
            font-size: 13px;
        }
        QPushButton:hover {
            background-color: #45475a;
            border-color: #89b4fa;
        }
        QPushButton#btnOk {
            background-color: #89b4fa;
            color: #1e1e2e;
            font-weight: bold;
            border: none;
        }
        QPushButton#btnOk:hover {
            background-color: #b4befe;
        }
        QLabel#statusLabel {
            color: #a6e3a1;
            font-size: 12px;
        }
    )");

    for (const auto &s : alreadySelected) {
        selectedExeNames.insert(s.toLower());
    }

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(16, 16, 16, 16);

    // Title
    auto *titleLabel = new QLabel(tr("🛡️  Выберите приложения для принудительного проксирования"));
    titleLabel->setStyleSheet("font-size: 14px; font-weight: bold; color: #89b4fa; margin-bottom: 4px;");
    mainLayout->addWidget(titleLabel);

    auto *hintLabel = new QLabel(tr("Отмеченные приложения будут направлены через прокси независимо от остальных правил."));
    hintLabel->setStyleSheet("color: #a6adc8; font-size: 12px;");
    hintLabel->setWordWrap(true);
    mainLayout->addWidget(hintLabel);

    // Search
    searchBox = new QLineEdit;
    searchBox->setPlaceholderText(tr("🔍  Поиск по имени приложения..."));
    searchBox->setClearButtonEnabled(true);
    mainLayout->addWidget(searchBox);

    // Top bar
    auto *topBar = new QHBoxLayout;
    statusLabel = new QLabel;
    statusLabel->setObjectName("statusLabel");
    topBar->addWidget(statusLabel);
    topBar->addStretch();
    btnSelectAll = new QPushButton(tr("Выбрать всё"));
    btnClearAll = new QPushButton(tr("Снять всё"));
    topBar->addWidget(btnSelectAll);
    topBar->addWidget(btnClearAll);
    mainLayout->addLayout(topBar);

    // App list
    appListWidget = new QListWidget;
    appListWidget->setSpacing(2);
    mainLayout->addWidget(appListWidget);

    // Bottom buttons
    auto *btnLayout = new QHBoxLayout;
    btnLayout->addStretch();
    btnCancel = new QPushButton(tr("Отмена"));
    btnOk = new QPushButton(tr("Применить"));
    btnOk->setObjectName("btnOk");
    btnLayout->addWidget(btnCancel);
    btnLayout->addWidget(btnOk);
    mainLayout->addLayout(btnLayout);

    // Load apps
    loadInstalledApps();
    filterApps("");

    // Connections
    connect(searchBox, &QLineEdit::textChanged, this, &DialogAppSelector::filterApps);
    connect(btnOk, &QPushButton::clicked, this, &QDialog::accept);
    connect(btnCancel, &QPushButton::clicked, this, &QDialog::reject);
    connect(btnSelectAll, &QPushButton::clicked, this, [=] {
        for (int i = 0; i < appListWidget->count(); i++) {
            auto *item = appListWidget->item(i);
            item->setCheckState(Qt::Checked);
            selectedExeNames.insert(item->data(Qt::UserRole).toString().toLower());
        }
        updateStatus();
    });
    connect(btnClearAll, &QPushButton::clicked, this, [=] {
        for (int i = 0; i < appListWidget->count(); i++) {
            auto *item = appListWidget->item(i);
            item->setCheckState(Qt::Unchecked);
            selectedExeNames.remove(item->data(Qt::UserRole).toString().toLower());
        }
        updateStatus();
    });
    connect(appListWidget, &QListWidget::itemChanged, this, [=](QListWidgetItem *item) {
        auto key = item->data(Qt::UserRole).toString().toLower();
        if (item->checkState() == Qt::Checked) {
            selectedExeNames.insert(key);
        } else {
            selectedExeNames.remove(key);
        }
        updateStatus();
    });

    updateStatus();
}

void DialogAppSelector::updateStatus() {
    statusLabel->setText(tr("Выбрано: %1 приложений").arg(selectedExeNames.size()));
}

void DialogAppSelector::loadInstalledApps() {
    QFileIconProvider iconProvider;
    QSet<QString> seen;

    auto addFromRegistry = [&](const QString &path) {
        QSettings reg(path, QSettings::NativeFormat);
        for (const auto &key : reg.childGroups()) {
            reg.beginGroup(key);
            QString name = reg.value("DisplayName").toString();
            QString loc = reg.value("InstallLocation").toString();
            reg.endGroup();
            if (name.isEmpty()) continue;
            // try to find exe
            QStringList candidates;
            if (!loc.isEmpty()) {
                QDir dir(loc);
                auto exes = dir.entryInfoList({"*.exe"}, QDir::Files);
                for (const auto &e : exes) candidates << e.absoluteFilePath();
            }
            if (candidates.isEmpty()) {
                AppEntry e;
                e.displayName = name;
                e.exeName = "";
                e.fullPath = "";
                e.icon = QApplication::style()->standardIcon(QStyle::SP_ComputerIcon);
                if (!seen.contains(name.toLower())) {
                    seen.insert(name.toLower());
                    allApps.append(e);
                }
            } else {
                for (const auto &exePath : candidates) {
                    QFileInfo fi(exePath);
                    auto exeName = fi.fileName().toLower();
                    if (seen.contains(exeName)) continue;
                    seen.insert(exeName);
                    AppEntry e;
                    e.displayName = name + " (" + fi.fileName() + ")";
                    e.exeName = fi.fileName();
                    e.fullPath = exePath;
                    e.icon = iconProvider.icon(fi);
                    allApps.append(e);
                    break; // one exe per app
                }
            }
        }
    };

    addFromRegistry("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    addFromRegistry("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    addFromRegistry("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

    // Sort by name
    std::sort(allApps.begin(), allApps.end(), [](const AppEntry &a, const AppEntry &b) {
        return a.displayName.toLower() < b.displayName.toLower();
    });
}

void DialogAppSelector::filterApps(const QString &filter) {
    appListWidget->blockSignals(true);
    appListWidget->clear();
    for (const auto &app : allApps) {
        if (!filter.isEmpty() && !app.displayName.contains(filter, Qt::CaseInsensitive)) continue;
        auto *item = new QListWidgetItem;
        item->setText(app.displayName);
        item->setIcon(app.icon);
        item->setData(Qt::UserRole, app.exeName.isEmpty() ? app.displayName : app.exeName);
        item->setCheckState(selectedExeNames.contains((app.exeName.isEmpty() ? app.displayName : app.exeName).toLower())
                                ? Qt::Checked : Qt::Unchecked);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        appListWidget->addItem(item);
    }
    appListWidget->blockSignals(false);
}

QStringList DialogAppSelector::getSelectedApps() const {
    QStringList result;
    for (const auto &exe : selectedExeNames) {
        if (!exe.isEmpty()) result << exe;
    }
    result.sort();
    return result;
}
