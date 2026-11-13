#include <interfaces/node.h>
#include <qt/createwalletdialog.h>
#include <qt/forms/ui_createwalletdialog.h>

#include <qt/guiutil.h>

#include <QPushButton>

CreateWalletDialog::CreateWalletDialog(QWidget* parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::CreateWalletDialog)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    ui->wallet_name_line_edit->setFocus(Qt::ActiveWindowFocusReason);

    connect(ui->wallet_name_line_edit, &QLineEdit::textEdited, [this](const QString& text) {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!text.isEmpty());
    });
}

CreateWalletDialog::~CreateWalletDialog()
{
    delete ui;
}

QString CreateWalletDialog::walletName() const
{
    return ui->wallet_name_line_edit->text();
}

bool CreateWalletDialog::isEncryptWalletChecked() const
{
    return ui->encrypt_wallet_checkbox->isChecked();
}

bool CreateWalletDialog::isDisablePrivateKeysChecked() const
{
    return false;
}

bool CreateWalletDialog::isMakeBlankWalletChecked() const
{
    return false;
}

bool CreateWalletDialog::isDescriptorWalletChecked() const
{
    return true;
}
