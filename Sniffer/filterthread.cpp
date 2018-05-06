#include "filterthread.h"
#include <QDebug>

FilterThread::FilterThread(HostInfo *hostInfo,const char*dev,QString filter)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    quitFg = false;

    this->filter = filter;
    //混杂模式
    this->handle = pcap_open_live(dev,65535,1,0,errBuf);

    if(!this->handle){
        printf("Open live dev is error: %s\n",errBuf);
        exit(1);
    }

    this->hostInfo = new HostInfo();
    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));
    filterDataBuffer=new QQueue< Package>();
    char *filetmp=".tmp";
    filename=filetmp;
}

// 退出线程
void FilterThread::quitThread()
{
    qDebug()<< "停止过滤抓包";
    quitFg = true;
    delete hostInfo;
    pcap_dump_close(dumpfile);
    pcap_close(this->handle);
    this->quit();
}
bool FilterThread::init()
{
    bpf_program fcode;
    QByteArray bytearray = this->filter.toLatin1();
    char * filterCS = bytearray.data();
    // 编译过滤器
    if(pcap_compile(handle, &fcode, filterCS, 1, my_htonl(my_inet_addr(hostInfo->netmask))) < 0){
        qDebug("过滤语法错误！");
        quitThread();
        // 释放设备列表
        return false;
    }
    // 设置过滤器
    if(pcap_setfilter(handle, &fcode) < 0){
        qDebug("设置过滤器出错！");
        quitThread();
        // 释放设备列表
        return false;
    }
    /* 打开堆文件 */
    dumpfile = pcap_dump_open(handle, filename);
    return true;
}
void FilterThread::filterStart()
{
    pcap_t *adhandle = this->handle;
    int res;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;
    char timestr[16] = {0};
    time_t local_tv_sec;
    struct tm *ltime;



    if(dumpfile==NULL)
    {
        qDebug()<<"\nError opening output file\n";
    }


    while (!quitFg) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            if(res == 0)
                 /* 超时时间到 */
                  continue;
            local_tv_sec = pktHeader->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
            QString usecs;
            usecs.sprintf("%06ld",pktHeader->ts.tv_usec);
            QString len = QString::number(pktHeader->len);
            Package getpackage;
            getpackage.time_s = QString(timestr);
            getpackage.time_us = usecs;
            memcpy(getpackage.data,pktData,pktHeader->len);
            getpackage.len = len;
            filterDataBuffer->enqueue(getpackage);
            pcap_dump((u_char *)dumpfile, pktHeader, pktData);
        }
    }
}
QQueue< Package> * FilterThread::getbuffp()
{
    return filterDataBuffer;
}
void FilterThread::run()
{
    if(init()){
        qDebug()<< "开始过滤抓包";
        filterStart();
    }
}
