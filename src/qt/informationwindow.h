#ifndef QT_INFORMATIONWINDOW_H
#define QT_INFORMATIONWINDOW_H

#include <QDateTime>
#include <QMainWindow>

#include "forms/ui_information.h"
#include <qt/clientmodel.h>

class InformationWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit InformationWindow(ClientModel* clientModel, QWidget *parent = nullptr);
private:
    Ui::Information ui;
    ClientModel* clientModel{nullptr};

private Q_SLOTS:
    void setNumConnections();
    void setNumBlocks(int count, const QDateTime& blockDate, double _verificationProgress, SyncType synctype);
    void setMempoolSize(long numberOfTxs, size_t dynUsage);
};

#endif // QT_INFORMATIONWINDOW_H