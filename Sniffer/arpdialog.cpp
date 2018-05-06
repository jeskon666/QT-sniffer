#include "arpdialog.h"
#include "ui_arpdialog.h"
#include <QDebug>
#include <QPushButton>

arpdialog::arpdialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::arpdialog)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Window | Qt::WindowTitleHint | Qt::CustomizeWindowHint | Qt::WindowCloseButtonHint);
}

arpdialog::~arpdialog()
{
    delete ui;
}

void arpdialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if(ui->buttonBox->button(QDialogButtonBox::Ok) == button)//判断按下的是否为"确定”按钮
    {
        //发送arp请求
        QVector<QString> arpdz;
        arpdz.append(ui->gmacEdit->text());
        arpdz.append(ui->gipEdit->text());
        arpdz.append(ui->dmacEdit->text());
        arpdz.append(ui->dipEdit->text());

        emit sendData(arpdz);
    }
}
