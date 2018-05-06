#ifndef ARPDIALOG_H
#define ARPDIALOG_H

#include <QDialog>
#include <QAbstractButton>

namespace Ui {
class arpdialog;
}

class arpdialog : public QDialog
{
    Q_OBJECT

public:
    explicit arpdialog(QWidget *parent = 0);
    ~arpdialog();

private slots:

    void on_buttonBox_clicked(QAbstractButton *button);

signals:
    void sendData(QVector<QString>);

private:
    Ui::arpdialog *ui;
};

#endif // ARPDIALOG_H
