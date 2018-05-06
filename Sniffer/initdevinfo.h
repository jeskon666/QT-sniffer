#ifndef INITDEVINFO_H
#define INITDEVINFO_H

#include "pcap.h"
#include "ethernet.h"
#include <QString>
#include <QVector>
#include <QQueue>
#include "usearp.h"
#include "filterthread.h"

#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_SRC_FILE 2
class initdevinfo : public QObject
{
    Q_OBJECT

public:
    initdevinfo();
    ~initdevinfo();

public:
    QVector<DEVInfo> *devall;
    QVector<DEVInfo> findalldevs();
    void getSelfMac(QString dev);
    void setselectdevinfo(QString dev);
    QString getselectMac(QString dev);

    void applyFilter(QString dev, QString rule);
    void stopFilter();
    void arpStart(QString dev, QVector<QString> arp);
    void arpStop();
    u_char hexStr2UChar(QString hexS);
    QQueue< Package> * transferbuffp();
    QQueue< Package> * opengumpfile(QString filename);
    QQueue< Package> *tmpbuffp;


protected:
    FilterThread *filterThread;
    usearp *usearp_p;
    pcap_t *handle;

    HostInfo hostInfo;
    GatewayInfo gatewayInfo;
};

#endif // INITDEVINFO_H
