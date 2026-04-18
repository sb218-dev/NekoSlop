#pragma once

#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QSettings>
#include <QIcon>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QSet>
#include <QStringList>
#include <QApplication>

// Beautiful app selector dialog for VPN bypass rules
class DialogAppSelector : public QDialog {
    Q_OBJECT
public:
    explicit DialogAppSelector(const QStringList &alreadySelected, QWidget *parent = nullptr);
    QStringList getSelectedApps() const;

private:
    void loadInstalledApps();
    void filterApps(const QString &filter);
    void toggleApp(const QString &exeName, bool checked);
    void updateStatus();


    QListWidget *appListWidget = nullptr;
    QLineEdit *searchBox = nullptr;
    QLabel *statusLabel = nullptr;
    QPushButton *btnOk = nullptr;
    QPushButton *btnCancel = nullptr;
    QPushButton *btnSelectAll = nullptr;
    QPushButton *btnClearAll = nullptr;

    struct AppEntry {
        QString displayName;
        QString exeName; // just the .exe basename
        QString fullPath;
        QIcon icon;
    };

    QList<AppEntry> allApps;
    QSet<QString> selectedExeNames;
};
