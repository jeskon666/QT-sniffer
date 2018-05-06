#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include "arpdialog.h"
#include "httpdialog.h"

#include <QDebug>
#include <QFile>
#define TIME 1
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_ui_(new Ui::MainWindow)
{
    main_ui_->setupUi(this);
    main_ui_->actionStop->setEnabled(false);
    main_ui_->actionReget->setEnabled(false);
    main_ui_->actionSave->setEnabled(false);
    main_ui_->actionClose->setEnabled(false);
    main_ui_->actionReload->setEnabled(false);
    dev = new initdevinfo();
    ethernetPacket = new YEthernetPacket();
    arppacket = new YArpPacket();
    eippacket = new YIPHeaderPacket();
    tcpheader=new YTcpHeader();
    ethernetPacket1 = new YEthernetPacket();
    arppacket1 = new YArpPacket();
    eippacket1 = new YIPHeaderPacket();
    udpheader = new YUdpHeader();
    icmpheader = new YICMPHeaderPacket();
    igmpheader = new YIGMPHeaderPacket();
    cache = new QVector<Package>;
    rule="";
    label1=new QLabel("Status: ");
    label2=new QLabel("ARP: 0");
    label3=new QLabel("TCP: 0");
    label4=new QLabel("UDP: 0");
    label5=new QLabel("ICMP: 0");
    label6=new QLabel("IGMP: 0");
    label7=new QLabel("UNKNOWN: 0");
    label8=new QLabel("Total: 0");


    initcombobox();
    initStatusBar();
    inittreewidget();

    initlisttable();
    connect(main_ui_->listtable,SIGNAL(cellClicked(int,int)),this,SLOT(listcellClickedslot(int,int)));
    initMenu();
    arp_n=0;
    tcp_n=0;
    udp_n=0;
    icmp_n=0;
    igmp_n=0;
    unknown_n=0;

    getDataFromFilterBufferTimer = new QTimer();
    connect(getDataFromFilterBufferTimer,SIGNAL(timeout()),this,SLOT(getDataFromFilterBufferSlot()));
    finalbuffp=NULL;
}

MainWindow::~MainWindow()
{
    delete main_ui_;
}


void MainWindow::initStatusBar()
{
    main_ui_->statusBar->addWidget(label1,1);
    main_ui_->statusBar->addWidget(label2,1);
    main_ui_->statusBar->addWidget(label3,1);
    main_ui_->statusBar->addWidget(label4,1);
    main_ui_->statusBar->addWidget(label5,1);
    main_ui_->statusBar->addWidget(label6,1);
    main_ui_->statusBar->addWidget(label7,1);
    main_ui_->statusBar->addWidget(label8,1);

    main_ui_->statusBar->setStyleSheet("color:#FFFFFF;background-color:#000000");
}
void MainWindow::initcombobox()
{

    for(int i = 0; i < dev->devall->length(); ++i){
        QPixmap icon  = style()->standardPixmap(QStyle::SP_DriveNetIcon);
        main_ui_->comboBox->addItem(icon,dev->devall->at(i).name+dev->devall->at(i).description);
    }
}
void MainWindow::inittreewidget()
{
    main_ui_->treeWidget->setHeaderHidden(true);
}
void MainWindow::initlisttable()
{
    //main_ui_->datatable->horizontalHeader()->setEnabled(false);
    main_ui_->listtable->setFrameShape(QFrame::NoFrame); //设置无边框
    main_ui_->listtable->setShowGrid(false); //设置不显示格子线
    main_ui_->listtable->setEditTriggers(QAbstractItemView::NoEditTriggers); //设置不可编辑
    main_ui_->listtable->verticalHeader()->setVisible(false); //设置垂直头不可见
    main_ui_->listtable->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一行
    //main_ui_->datatable->verticalHeader()->setDefaultSectionSize(10); //设置行高
    main_ui_->listtable->horizontalHeader()->setStretchLastSection(true); //设置表格充满，即行位不留空
    main_ui_->listtable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    main_ui_->listtable->setSelectionMode ( QAbstractItemView::SingleSelection); //设置选择模式，选择单行
    main_ui_->listtable->verticalHeader()->setDefaultSectionSize(20);
}

QString MainWindow::getChosedDev()
{
    QString str;
    str=main_ui_->comboBox->currentText();
    QStringList list=str.split("}");

    return list.at(0)+'}';
}
void MainWindow::getDataFromFilterBufferSlot()
{
    if(finalbuffp!=NULL){
        if(!finalbuffp->isEmpty()){
        filterUpdateData(finalbuffp->dequeue());
        }
    }
}
void MainWindow::on_actionStart_triggered()
{
    //qDebug()<<getDataFromFilterBufferTimer->isActive();
    if(getDataFromFilterBufferTimer->isActive())
        getDataFromFilterBufferTimer->stop();
    //qDebug()<<getDataFromFilterBufferTimer->isActive();
    getDataFromFilterBufferTimer->start(TIME);
    dev->applyFilter(getChosedDev(),rule);
    main_ui_->actionStart->setEnabled(false);
    main_ui_->actionStop->setEnabled(true);
    main_ui_->actionReget->setEnabled(true);
    main_ui_->actionSave->setEnabled(false);
    main_ui_->actionClose->setEnabled(false);
    main_ui_->actionReload->setEnabled(false);
    main_ui_->comboBox->setEnabled(false);
    finalbuffp=dev->transferbuffp();
}
void MainWindow::on_actionStop_triggered()
{
    getDataFromFilterBufferTimer->stop();
    main_ui_->actionStart->setEnabled(true);
    main_ui_->actionStop->setEnabled(false);
    main_ui_->actionReget->setEnabled(false);
    main_ui_->actionSave->setEnabled(true);
    main_ui_->actionClose->setEnabled(true);
    main_ui_->actionReload->setEnabled(true);
    main_ui_->comboBox->setEnabled(true);
    dev->stopFilter();
    finalbuffp=NULL;
}
void MainWindow::on_actionReget_triggered()
{
    getDataFromFilterBufferTimer->stop();

    //仅重新开始
    arp_n=0;
    tcp_n=0;
    udp_n=0;
    icmp_n=0;
    igmp_n=0;
    unknown_n=0;
    main_ui_->listtable->clearContents();
    main_ui_->listtable->setRowCount(0);
    cache->clear();
    dev->stopFilter();
    finalbuffp=NULL;

    getDataFromFilterBufferTimer->start(TIME);
    dev->applyFilter(getChosedDev(),rule);
    finalbuffp=dev->transferbuffp();
}

void MainWindow::on_useglqButton_clicked()
{
    rule=main_ui_->glqEdit->text();
    if(main_ui_->actionStart->isEnabled()==false){
        getDataFromFilterBufferTimer->stop();
        dev->stopFilter();
        finalbuffp=NULL;
        getDataFromFilterBufferTimer->start(TIME);
        dev->applyFilter(getChosedDev(),rule);
        finalbuffp=dev->transferbuffp();
    }
}

void MainWindow::on_actionSave_triggered()
{
    //保存成文件
    QFile file(".tmp");
    if(file.exists()==false)
        return;

    main_ui_->actionSave->setEnabled(false);
    QString fileName = QFileDialog::getSaveFileName(this,
            QString("文件另存为"),
            "",
            tr("Config Files (*.pcap)"));
    file.rename(fileName);

}
void MainWindow::on_actionopen_triggered()
{
    getDataFromFilterBufferTimer->start(TIME);
    QString fileName = QFileDialog::getOpenFileName(this,QString("打开"),"","*.pcap");
    finalbuffp=dev->opengumpfile(fileName);

}
void MainWindow::on_actionhttp_triggered()
{
    httpDialog *htdilog = new httpDialog();

    htdilog->initEdit(httptext,httplen);
    htdilog->exec();
}
void MainWindow::on_actionClose_triggered()
{
    main_ui_->actionStart->setEnabled(true);
    main_ui_->actionStop->setEnabled(false);
    main_ui_->actionReget->setEnabled(false);
    main_ui_->actionSave->setEnabled(false);
    main_ui_->actionClose->setEnabled(false);
    main_ui_->actionReload->setEnabled(false);
    main_ui_->listtable->clearContents();
    main_ui_->listtable->setRowCount(0);
    main_ui_->dataEdit->clear();
    main_ui_->treeWidget->clear();
    cache->clear();
    arp_n=0;
    tcp_n=0;
    udp_n=0;
    icmp_n=0;
    igmp_n=0;
    unknown_n=0;
    QTreeWidgetItem * default_t=new QTreeWidgetItem(main_ui_->treeWidget,
                QStringList(QString(" ")));
    main_ui_->treeWidget->addTopLevelItem(default_t);
    finalbuffp=NULL;
    //清理所有，复原到初始状态
}

void MainWindow::on_actionReload_triggered()
{
    //不做任何操作或刷新界面
}

void MainWindow::on_actionexit_triggered()
{
    qApp->exit(0);
}
void MainWindow::on_actionstartARP_triggered()
{
    arpdialog *arp = new arpdialog();
    connect(arp,SIGNAL(sendData(QVector<QString>)), this, SLOT(receiveData(QVector<QString>)));
    if(arp->exec()==QDialog::Accepted)
    {
        qDebug()<<"确认操作";

    }
    else
        qDebug()<<"取消操作";
}
void MainWindow::on_actionstopARP_triggered()
{
    if(main_ui_->actionStart->isEnabled()==true){
        main_ui_->comboBox->setEnabled(true);
    }
    dev->arpStop();
}
void MainWindow::initMenu()
{

    QActionGroup *grp = new QActionGroup(this);

    grp->addAction(main_ui_->actionViewip);
    grp->addAction(main_ui_->actionViewmac);
    //connect(grp, SIGNAL(triggered(QAction*)),this, SLOT(setFormStyle(QAction*)));

    main_ui_->actionViewmac->setCheckable(true);
    main_ui_->actionViewmac->setChecked(true);
    //grp->setExclusive(true);
}

void MainWindow::receiveData(QVector<QString> arp)
{

    main_ui_->comboBox->setEnabled(false);
    dev->arpStart(getChosedDev(),arp);
}
void MainWindow::filterUpdateData(Package out_get)
{
    const u_char * package;
    package=out_get.data;
    ethernetPacket1->setData(package);

    u_short typetmp=ethernetPacket1->getEtherNetType();
    if(typetmp == my_ntohs(ARP_TYPE)){
        arppacket1->setData(package);
        int RowCont;
        cache->append(out_get);
        RowCont=main_ui_->listtable->rowCount();

        QString num=QString::number(RowCont+1);
        arp_n++;
        label8->setText("Total: "+num);
        label2->setText("ARP: "+QString::number(arp_n));
        main_ui_->listtable->insertRow(RowCont);//增加一行
        main_ui_->listtable->setItem(RowCont,4,new QTableWidgetItem("ARP"));
        //插入元素
        main_ui_->listtable->setItem(RowCont,0,new QTableWidgetItem(num));
        main_ui_->listtable->setItem(RowCont,1,new QTableWidgetItem(out_get.time_s+"."+out_get.time_us));
        main_ui_->listtable->setItem(RowCont,5,new QTableWidgetItem(out_get.len));

        if(main_ui_->actionViewmac->isChecked()==true)
        {
            main_ui_->listtable->setItem(RowCont,2,new QTableWidgetItem(ethernetPacket1->getEtherSrcMacAdd()));
            main_ui_->listtable->setItem(RowCont,3,new QTableWidgetItem(ethernetPacket1->getEtherDestMacAdd()));
        }
        else
        {
            main_ui_->listtable->setItem(RowCont,2,new QTableWidgetItem(arppacket1->getSourceIpAddStr()));
            main_ui_->listtable->setItem(RowCont,3,new QTableWidgetItem(arppacket1->getDestIpAddStr()));
        }
        for(int i=0;i<6;i++)
        {
            QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
            if (tmptitem)
            {
                 tmptitem->setBackgroundColor(QColor("navajowhite"));
            }
        }
    }
    else if(typetmp == my_ntohs(IP_TYPE)){
        eippacket1->setData(package);
        int RowCont;
        cache->append(out_get);
        RowCont=main_ui_->listtable->rowCount();
        //qDebug()<<RowCont;
        QString num=QString::number(RowCont+1);
        label8->setText("Total: "+num);
        main_ui_->listtable->insertRow(RowCont);//增加一行
        main_ui_->listtable->setItem(RowCont,4,new QTableWidgetItem(eippacket1->getProtocolType()));
        //插入元素
        main_ui_->listtable->setItem(RowCont,0,new QTableWidgetItem(num));
        main_ui_->listtable->setItem(RowCont,1,new QTableWidgetItem(out_get.time_s+"."+out_get.time_us));
        main_ui_->listtable->setItem(RowCont,5,new QTableWidgetItem(out_get.len));

        if(main_ui_->actionViewmac->isChecked()==true)
        {
            main_ui_->listtable->setItem(RowCont,2,new QTableWidgetItem(ethernetPacket1->getEtherSrcMacAdd()));
            main_ui_->listtable->setItem(RowCont,3,new QTableWidgetItem(ethernetPacket1->getEtherDestMacAdd()));   
        }
        else
        {
            main_ui_->listtable->setItem(RowCont,2,new QTableWidgetItem(eippacket1->getSourceIpAddStr()));
            main_ui_->listtable->setItem(RowCont,3,new QTableWidgetItem(eippacket1->getDestIpAddStr()));
        }
        if(eippacket1->getProtocolType()=="TCP"){
            for(int i=0;i<6;i++)
            {
                QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
                if (tmptitem)
                {
                     tmptitem->setBackgroundColor(QColor("palegreen"));
                }
            }
            tcp_n++;
            label3->setText("TCP: "+QString::number(tcp_n));
        }
        if(eippacket1->getProtocolType()=="UDP"){
            for(int i=0;i<6;i++)
            {
                QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
                if (tmptitem)
                {
                     tmptitem->setBackgroundColor(QColor("lightskyblue"));
                }
            }
            udp_n++;
            label4->setText("UDP: "+QString::number(udp_n));
        }
        if(eippacket1->getProtocolType()=="ICMP"){
            for(int i=0;i<6;i++)
            {
                QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
                if (tmptitem)
                {
                     tmptitem->setBackgroundColor(QColor("plum"));
                }
            }
            icmp_n++;
            label5->setText("ICMP: "+QString::number(icmp_n));
        }
        if(eippacket1->getProtocolType()=="IGMP"){
            for(int i=0;i<6;i++)
            {
                QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
                if (tmptitem)
                {
                     tmptitem->setBackgroundColor(QColor("lightpink"));
                }
            }
            igmp_n++;
            label6->setText("UDP: "+QString::number(igmp_n));
        }
        if(eippacket1->getProtocolType()=="UNKNOWN"){
            for(int i=0;i<6;i++)
            {
                QTableWidgetItem *tmptitem = main_ui_->listtable->item(RowCont,i);
                if (tmptitem)
                {
                     tmptitem->setBackgroundColor(QColor("red"));
                }
            }
            unknown_n++;
            label7->setText("UNKNOWN: "+QString::number(unknown_n));
        }
    }
    main_ui_->listtable->scrollToBottom();
    /*设置让某个单元格或某行选中*/
    //main_ui_->listtable->setCurrentCell(0, QItemSelectionModel::Select);
}
void MainWindow::listcellClickedslot(int row, int column)
{
    main_ui_->actionhttp->setEnabled(false);
    main_ui_->treeWidget->clear();
    main_ui_->dataEdit->clear();
    //main_ui_->treeWidget->clearSelection();
    const u_char * package;
    package=cache->at(row).data;
    ethernetPacket->setData(package);
    int data_len=cache->at(row).len.toInt();
    //qDebug()<<ethernetPacket->getEtherNetType();
    const u_char * p=cache->at(row).data;
    int i,j,k;


    for(i=0;;++i){
        QString hang;
        hang.sprintf("%04x    ",i*16);
        main_ui_->dataEdit->appendPlainText(hang);
        for(j=0;j<16;++j){
            QString Buf;
            Buf.sprintf("%02x ",*(unsigned char *)(p+i*16+j));
            main_ui_->dataEdit->insertPlainText(Buf);
            if(j==7) main_ui_->dataEdit->insertPlainText(" ");
            if(i*16+j==data_len-1)
                break;
        }
        main_ui_->dataEdit->insertPlainText("   ");
        if(j<7)
            main_ui_->dataEdit->insertPlainText(" ");
        if(j<15){
            QString bc(3*(15-j),' ');
            main_ui_->dataEdit->insertPlainText(bc);
        }
        for(k=0;k<16;++k){
            QString chr;
            if(*(unsigned char *)(p+i*16+k)>126||*(unsigned char *)(p+i*16+k)<32)
                chr=".";
            else
                chr.sprintf("%c",*(unsigned char *)(p+i*16+k));
            main_ui_->dataEdit->insertPlainText(chr);
            if(k==7) main_ui_->dataEdit->insertPlainText(" ");
            if(i*16+k==data_len-1)
                break;
        }
        if(i*16+k==data_len-1)
            break;
    }
    QTreeWidgetItem *frameitem=getframe(row,data_len);
    main_ui_->treeWidget->addTopLevelItem(frameitem);

    if(ethernetPacket->getEtherNetType() == my_ntohs(ARP_TYPE)){
        arppacket->setData(package);
        QTreeWidgetItem *ethitem=geteth("ARP (0x0806)");
        main_ui_->treeWidget->addTopLevelItem(ethitem);
        QTreeWidgetItem *additem=getadrp();
        main_ui_->treeWidget->addTopLevelItem(additem);
    }
    else if(ethernetPacket->getEtherNetType() == my_ntohs(IP_TYPE)){
        eippacket->setData(package);
        QTreeWidgetItem *ethitem=geteth("IPv4 (0x0800)");
        main_ui_->treeWidget->addTopLevelItem(ethitem);
        QTreeWidgetItem *ipitem=getipv4(eippacket->getProtocolType());
        main_ui_->treeWidget->addTopLevelItem(ipitem);
        //qDebug()<<eippacket->gettotallen();
        if(eippacket->getProtocolType()=="TCP")
        {
            tcpheader->setData(package);
            QTreeWidgetItem *tcpitem=gettcp(data_len);
            main_ui_->treeWidget->addTopLevelItem(tcpitem);
            if(tcpheader->getDstPort()=="80"||tcpheader->getSrcPort()=="80"){
                int tcp_len=tcpheader->getlen().toInt();
                if(data_len>(tcp_len+34)){
                    QString http=QString("Hypertext Transfer Protocol");
                    QTreeWidgetItem *httpitem=new QTreeWidgetItem(QStringList(http));
                    main_ui_->treeWidget->addTopLevelItem(httpitem);
                    //memcpy(httptext,package+14+20+20,data_len-54);
                    //httplen=data_len-54;
                    char tmp[1800];
                    httplen=data_len-tcp_len-34;
                    strncpy(tmp,(const char*)(package+14+20+tcp_len),httplen);//0d0a不要
                    httptext=QString(tmp);
                    main_ui_->actionhttp->setEnabled(true);
                }
            }
        }
        else if(eippacket->getProtocolType()=="UDP")
        {
            udpheader->setData(package);
            QTreeWidgetItem *udpitem=getudp();
            main_ui_->treeWidget->addTopLevelItem(udpitem);
        }
        else if(eippacket->getProtocolType()=="ICMP")
        {
            icmpheader->setData(package);
            QTreeWidgetItem *icmpitem=geticmp();
            main_ui_->treeWidget->addTopLevelItem(icmpitem);
        }
        else if(eippacket->getProtocolType()=="IGMP")
        {
            QTreeWidgetItem *igmpitem=getigmp();
            main_ui_->treeWidget->addTopLevelItem(igmpitem);
        }
    }
}

QTreeWidgetItem * MainWindow::getframe(int row,int len)
{
    QString frame;
    frame+="Frame ";
    frame+=QString::number(row+1);
    frame+=QString(": %1 bytes on wire (%2 bits), %1 bytes captured (%2 bit) on interface 0").arg(QString::number(len),QString::number(8*len));
    QTreeWidgetItem * frameitem=new QTreeWidgetItem(
                QStringList(frame));
    QTreeWidgetItem *frameitem_1 = new QTreeWidgetItem(frameitem,
                                QStringList(QString("Frame Length: %1 bytes (%2 bits)").arg(QString::number(len),QString::number(8*len))));
    frameitem->addChild(frameitem_1);
    return frameitem;
}
QTreeWidgetItem * MainWindow::geteth(QString type1)
{
    QString eth;
    eth+="Ethernet II, Src: ";
    QString smac=ethernetPacket->getEtherSrcMacAdd();
    eth+=smac;
    eth+=", Dst: ";
    QString dmac=ethernetPacket->getEtherDestMacAdd();
    eth+=dmac;
    QTreeWidgetItem * ethitem=new QTreeWidgetItem(QStringList(eth));
    QTreeWidgetItem *ethitem_1 = new QTreeWidgetItem(ethitem,
                                QStringList(QString("%1%2").arg("Destination: ",dmac)));
    QTreeWidgetItem *ethitem_2 = new QTreeWidgetItem(ethitem,
                                QStringList(QString("%1%2").arg("Source: ",smac)));
    QTreeWidgetItem *ethitem_3 = new QTreeWidgetItem(ethitem,
                                QStringList(QString("%1%2").arg("Type: ",type1)));
    ethitem->addChild(ethitem_1);
    ethitem->addChild(ethitem_2);
    ethitem->addChild(ethitem_3);
    return ethitem;
}
QTreeWidgetItem * MainWindow::getadrp()
{
    QString add;
    add+="Address Resolution Protocol";
    QTreeWidgetItem *additem=new QTreeWidgetItem(QStringList(add));
    QString type;
    QString tmp;
    if(my_ntohs(arppacket->getOperationField())==1)
        tmp="Opcode: request 0x";
    else
        tmp="Opcode: reply 0x";
    QTreeWidgetItem *additem_0 = new QTreeWidgetItem(additem,
                                QStringList(QString("%1%2").arg(tmp,type.sprintf("%04x",my_ntohs(arppacket->getOperationField())))));
    QTreeWidgetItem *additem_1 = new QTreeWidgetItem(additem,
                                QStringList(QString("%1%2").arg("Sender MAC address: ",arppacket->getSourceMacAdd())));
    QTreeWidgetItem *additem_2 = new QTreeWidgetItem(additem,
                                QStringList(QString("%1%2").arg("Sender IP address: ",arppacket->getSourceIpAddStr())));
    QTreeWidgetItem *additem_3 = new QTreeWidgetItem(additem,
                                QStringList(QString("%1%2").arg("Target MAC address: ",arppacket->getDestMacAdd())));

    QTreeWidgetItem *additem_4 = new QTreeWidgetItem(additem,
                                QStringList(QString("%1%2").arg("Target IP address: ",arppacket->getDestIpAddStr())));
    additem->addChild(additem_0);
    additem->addChild(additem_1);
    additem->addChild(additem_2);
    additem->addChild(additem_3);
    additem->addChild(additem_4);
    return additem;
}
QTreeWidgetItem * MainWindow::getipv4(QString type2)
{
    QString ipv4;
    ipv4+="Internet Protocol Version 4, Src: ";
    QString sip=eippacket->getSourceIpAddStr();
    ipv4+=sip;
    ipv4+=", Dst: ";
    QString dip=eippacket->getDestIpAddStr();
    ipv4+=dip;
    QTreeWidgetItem *ipv4item=new QTreeWidgetItem(QStringList(ipv4));
    QTreeWidgetItem *ipv4item_1=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Version: 4")));
    QTreeWidgetItem *ipv4item_2=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Header Length: 20bytes")));
    QTreeWidgetItem *ipv4item_3=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Protocol: %1").arg(type2)));
    QTreeWidgetItem *ipv4item_4=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Source: %1").arg(sip)));

    QTreeWidgetItem *ipv4item_5=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Destination: %1").arg(dip)));
    QTreeWidgetItem *ipv4item_6=new QTreeWidgetItem(ipv4item,
                                                    QStringList(QString("Total Length: %1").arg(eippacket->gettotallen())));


    ipv4item->addChild(ipv4item_1);
    ipv4item->addChild(ipv4item_2);
    ipv4item->addChild(ipv4item_3);
    ipv4item->addChild(ipv4item_4);
    ipv4item->addChild(ipv4item_5);
    ipv4item->addChild(ipv4item_6);
    return ipv4item;
}
QTreeWidgetItem * MainWindow::gettcp(int datalen)
{
    QString sp=tcpheader->getSrcPort();
    QString dp=tcpheader->getDstPort();

    QString tcp=QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Seq: %3, Ack: %4, Len: %5").arg(
                sp,dp,tcpheader->getseqnum(),tcpheader->getack(),QString::number(datalen-34-(tcpheader->getlen().toInt())));
    QTreeWidgetItem *tcpitem=new QTreeWidgetItem(QStringList(tcp));
    QTreeWidgetItem *tcpitem_1=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Source Port: %1").arg(sp)));
    QTreeWidgetItem *tcpitem_2=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Destination Port: %1").arg(dp)));
    QTreeWidgetItem *tcpitem_3=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Sequnce number: %1").arg(tcpheader->getseqnum())));
    QTreeWidgetItem *tcpitem_4=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Acknowledgment number: %1").arg(tcpheader->getack())));
    QTreeWidgetItem *tcpitem_5=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Header Length: %1 bytes").arg(tcpheader->getlen())));
    QTreeWidgetItem *tcpitem_6=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Flags: 0x0%1").arg(tcpheader->getFlag())));
    QString tmp;
    tmp.sprintf("%d",my_ntohs(tcpheader->getData().Win));
    QTreeWidgetItem *tcpitem_7=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Window size value: %1").arg(tmp)));
    QTreeWidgetItem *tcpitem_8=new QTreeWidgetItem(tcpitem,
                                                    QStringList(QString("Checksum: 0x%1").arg(tcpheader->getchecksum())));
    tcpitem->addChild(tcpitem_1);
    tcpitem->addChild(tcpitem_2);
    tcpitem->addChild(tcpitem_3);
    tcpitem->addChild(tcpitem_4);
    tcpitem->addChild(tcpitem_5);
    tcpitem->addChild(tcpitem_6);
    tcpitem->addChild(tcpitem_7);
    tcpitem->addChild(tcpitem_8);
    return tcpitem;
}
QTreeWidgetItem * MainWindow::getudp()
{
    QString sp=udpheader->getSrcPort();
    QString dp=udpheader->getDstPort();

    QString udp=QString("User Datagram Protocol, Src Port: %1, Dst Port: %2").arg(
                sp,dp);
    QTreeWidgetItem *udpitem=new QTreeWidgetItem(QStringList(udp));
    QTreeWidgetItem *udpitem_1=new QTreeWidgetItem(udpitem,
                                                    QStringList(QString("Source Port: %1").arg(sp)));
    QTreeWidgetItem *udpitem_2=new QTreeWidgetItem(udpitem,
                                                    QStringList(QString("Destination Port: %1").arg(dp)));
    QTreeWidgetItem *udpitem_3=new QTreeWidgetItem(udpitem,
                                                    QStringList(QString("Length: %1").arg(udpheader->getlen())));
    QTreeWidgetItem *udpitem_4=new QTreeWidgetItem(udpitem,
                                                    QStringList(QString("Checksum: 0x%1").arg(udpheader->getchecksum())));


    udpitem->addChild(udpitem_1);
    udpitem->addChild(udpitem_2);
    udpitem->addChild(udpitem_3);
    udpitem->addChild(udpitem_4);
    return udpitem;
}
QTreeWidgetItem * MainWindow::geticmp()
{
    QString icmp=QString("Internet Control Message Protocol");
    QTreeWidgetItem *icmpitem=new QTreeWidgetItem(QStringList(icmp));
    QString type = icmpheader->getType();
    if(type=="0") type+=" (Echo reply)";
    else type+=" (Echo request)";
    QTreeWidgetItem *icmpitem_1=new QTreeWidgetItem(icmpitem,
                                                    QStringList(QString("Type: %1").arg(type)));
    QTreeWidgetItem *icmpitem_2=new QTreeWidgetItem(icmpitem,
                                                    QStringList(QString("Code: %1").arg(icmpheader->getCode())));
    QTreeWidgetItem *icmpitem_3=new QTreeWidgetItem(icmpitem,
                                                    QStringList(QString("Checksum: 0x%1").arg(icmpheader->getchecksum())));
    QTreeWidgetItem *icmpitem_4=new QTreeWidgetItem(icmpitem,
                                                    QStringList(QString("Identifier: 0x%1").arg(icmpheader->getident())));
    QTreeWidgetItem *icmpitem_5=new QTreeWidgetItem(icmpitem,
                                                    QStringList(QString("Sequence: 0x%1").arg(icmpheader->getSeq())));

    icmpitem->addChild(icmpitem_1);
    icmpitem->addChild(icmpitem_2);
    icmpitem->addChild(icmpitem_3);
    icmpitem->addChild(icmpitem_4);
    icmpitem->addChild(icmpitem_5);
    return icmpitem;
}
QTreeWidgetItem * MainWindow::getigmp()
{
    QString igmp=QString("Internet Group Management Protocol");
    QTreeWidgetItem *igmpitem=new QTreeWidgetItem(QStringList(igmp));
    return igmpitem;
}
