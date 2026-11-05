#include <qt/informationwindow.h>

InformationWindow::InformationWindow(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    setWindowTitle(tr("Information"));
    resize(400, 300);
}