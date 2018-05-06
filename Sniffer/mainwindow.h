#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "initdevinfo.h"
#include "packetprotocol.h"
#include <QTreeWidgetItem>
#include <QMainWindow>
#include <QFileDialog>
#include <QVector>
#include <QLabel>
#include <QTimer>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void initStatusBar();
    void initcombobox();
    void inittreewidget();
    void initlisttable();
    void initdatetable();
    void initMenu();
    QString getChosedDev();
    void filterUpdateData(Package);
    QTreeWidgetItem * getframe(int row,int len);
    QTreeWidgetItem * geteth(QString type1);
    QTreeWidgetItem * getadrp();
    QTreeWidgetItem * getipv4(QString type2);
    QTreeWidgetItem * gettcp(int datalen);
    QTreeWidgetItem * getudp();
    QTreeWidgetItem * geticmp();
    QTreeWidgetItem * getigmp();
private:
    initdevinfo  *dev;
    QTimer *getDataFromFilterBufferTimer;

private slots:

    void on_useglqButton_clicked();

    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void on_actionReget_triggered();

    void on_actionSave_triggered();

    void on_actionClose_triggered();

    void on_actionReload_triggered();

    void on_actionexit_triggered();

    void on_actionstartARP_triggered();
    void on_actionstopARP_triggered();
    void listcellClickedslot(int, int);

    void receiveData(QVector<QString>);   //接收arp传递过来的数据的槽

    void on_actionhttp_triggered();
    void getDataFromFilterBufferSlot();

    void on_actionopen_triggered();

private:
    Ui::MainWindow *main_ui_;
    YEthernetPacket * ethernetPacket1;
    YArpPacket *arppacket1;
    YIPHeaderPacket *eippacket1;
    YEthernetPacket * ethernetPacket;
    YArpPacket *arppacket;
    YIPHeaderPacket *eippacket;
    YTcpHeader *tcpheader;
    YUdpHeader *udpheader;
    YICMPHeaderPacket *icmpheader;
    YIGMPHeaderPacket *igmpheader;
    QVector<Package> *cache;
    QString rule;
    QLabel *label1;
    QLabel *label2;
    QLabel *label3;
    QLabel *label4;
    QLabel *label5;
    QLabel *label6;
    QLabel *label7;
    QLabel *label8;
    int arp_n;
    int tcp_n;
    int udp_n;
    int icmp_n;
    int igmp_n;
    int unknown_n;
    QString httptext;
    int httplen;
    QQueue<Package> *finalbuffp;
};

#endif // MAINWINDOW_H
