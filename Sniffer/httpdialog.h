#ifndef HTTPDIALOG_H
#define HTTPDIALOG_H

#include <QDialog>

namespace Ui {
class httpDialog;
}

class httpDialog : public QDialog
{
    Q_OBJECT

public:
    explicit httpDialog(QWidget *parent = 0);

    ~httpDialog();
    void initEdit(QString text, int length);

private:
    Ui::httpDialog *ui;
};

#endif // HTTPDIALOG_H
