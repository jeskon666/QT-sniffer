#include "httpdialog.h"
#include "ui_httpdialog.h"

httpDialog::httpDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::httpDialog)
{
    setWindowFlags(Qt::Window | Qt::WindowTitleHint | Qt::CustomizeWindowHint | Qt::WindowCloseButtonHint);
    ui->setupUi(this);
}
void httpDialog::initEdit(QString text, int length)
{
    ui->t_label->setAlignment(Qt::AlignCenter);    // 设置对齐方式
    ui->label->setText(QString::number(length));
    ui->label->setAlignment(Qt::AlignCenter);
    ui->httpEdit->setPlainText(text);
}
httpDialog::~httpDialog()
{
    delete ui;
}
