#include <qt/informationwindow.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <chainparams.h>
#include <interfaces/node.h>

#include <QDateTime>

InformationWindow::InformationWindow(ClientModel* _clientModel, QWidget *parent)
    : QMainWindow(parent),
      clientModel(_clientModel)
{
    ui.setupUi(this);
    setWindowTitle(tr("Information"));

    if (!clientModel) return;

    // Static info
    ui.clientVersion->setText(clientModel->formatFullVersion());
    ui.clientUserAgent->setText(clientModel->formatSubVersion());
    ui.dataDir->setText(clientModel->dataDir());
    ui.blocksDir->setText(clientModel->blocksDir());
    ui.startupTime->setText(clientModel->formatClientStartupTime());
    ui.networkName->setText(QString::fromStdString(Params().NetworkIDString()));

    // Dynamic info
    setNumConnections();
    setNumBlocks(
        clientModel->node().getNumBlocks(),
        QDateTime::fromSecsSinceEpoch(clientModel->node().getLastBlockTime()).toLocalTime(),
        0.0, // unused progress percentage, set to whatever
        SyncType::BLOCK_SYNC
    );
    setMempoolSize(clientModel->node().getMempoolSize(), clientModel->node().getMempoolDynamicUsage());

    // Connect signals for live updates
    connect(clientModel, &ClientModel::numConnectionsChanged, this, &InformationWindow::setNumConnections);
    connect(clientModel, &ClientModel::numBlocksChanged, this, &InformationWindow::setNumBlocks);
    connect(clientModel, &ClientModel::mempoolSizeChanged, this, &InformationWindow::setMempoolSize);
}

void InformationWindow::setNumConnections()
{
    if (!clientModel) return;

    QString connections = QString::number(clientModel->getNumConnections()) + " (";
    connections += tr("In:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_IN)) + " / ";
    connections += tr("Out:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_OUT)) + ")";

    if (!clientModel->node().getNetworkActive()) {
        connections += " (" + tr("Network activity disabled") + ")";
    }

    ui.numberOfConnections->setText(connections);
}

void InformationWindow::setNumBlocks(int count, const QDateTime& blockDate, double _verificationProgress, SyncType synctype)
{
    if (synctype == SyncType::BLOCK_SYNC) {
        ui.numberOfBlocks->setText(QString::number(count));
        ui.lastBlockTime->setText(blockDate.toString());
    }
}

void InformationWindow::setMempoolSize(long numberOfTxs, size_t dynUsage)
{
    ui.mempoolNumberTxs->setText(QString::number(numberOfTxs));

    if (dynUsage < 1000000) {
        ui.mempoolSize->setText(QObject::tr("%1 kB").arg(dynUsage / 1000.0, 0, 'f', 2));
    } else {
        ui.mempoolSize->setText(QObject::tr("%1 MB").arg(dynUsage / 1000000.0, 0, 'f', 2));
    }
}