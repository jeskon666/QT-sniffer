// ---------------------------------------------
// 过滤抓包线程
// ---------------------------------------------
#ifndef FILTERTHREAD_H
#define FILTERTHREAD_H
#include <QThread>
#include <QQueue>
#include "ethernet.h"
#include "pcap.h"

class FilterThread : public QThread
{
    Q_OBJECT

public:

    FilterThread(HostInfo *hostInfo,const char*dev,QString filter);

    void quitThread();
    QQueue< Package> * getbuffp();
private:
    bool init();
    void filterStart();
    void run();
    pcap_t * handle;
    HostInfo *hostInfo;
    QString filter;
    bool quitFg;
    QQueue< Package> *filterDataBuffer;
    const char* filename;
    pcap_dumper_t *dumpfile;
};

#endif // FILTERTHREAD_H
