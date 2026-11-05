#ifndef QT_INFORMATIONWINDOW_H
#define QT_INFORMATIONWINDOW_H

#include "forms/ui_information.h"

#include <QMainWindow>

class InformationWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit InformationWindow(QWidget *parent = nullptr);
private:
    Ui::Information ui;
};

#endif // QT_INFORMATIONWINDOW_H