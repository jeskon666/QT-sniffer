#include "initdevinfo.h"
#include <packet32.h>
#include <pcap.h>
#include <ntddndis.h>
#include <QDebug>

initdevinfo::initdevinfo()
{
    qRegisterMetaType<Package>("Package");

    handle = NULL;
    memset(hostInfo.mac,0x00,6);

    filterThread=NULL;
    usearp_p=NULL;
    devall=new QVector<DEVInfo>(findalldevs());
    tmpbuffp=NULL;
}

initdevinfo::~initdevinfo()
{
    if(handle != NULL)
        pcap_close(handle);
}
// 扫描本机所有的适配器，并获取每个适配器的信息
QVector<DEVInfo> initdevinfo::findalldevs()
{
    pcap_if_t *alldevs;
    QVector<DEVInfo> allDev;
    DEVInfo tempDevInfo;
    pcap_if_t *p;

    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地机器设备列表
    if(pcap_findalldevs(&alldevs,errbuf) == -1){
        printf("Find all devices is error: %s\n",errbuf);
        exit(1);
    }

    for(p = alldevs;p;p = p->next){
        tempDevInfo.name = p->name;
        if(p->description){
            tempDevInfo.description = p->description;
        }
        else{
            tempDevInfo.description = "(No description available)";
        }

        pcap_addr_t *a;

        for(a = p->addresses;a;a = a->next){
            switch(a->addr->sa_family){
                case AF_INET:
                    tempDevInfo.familyName = "AF_INET";
                    if (a->addr){
                        tempDevInfo.address = my_iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    }
                    if (a->netmask){
                        tempDevInfo.netmask = my_iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                    }
                    if (a->broadaddr)
                        //printf("\tBroadcast Address: %s\n",my_iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                    if (a->dstaddr)
                        //printf("\tDestination Address: %s\n",my_iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                    break;
                case AF_INET6:
                    if (a->addr)
                        //printf("\tAddress: %d\n", inet_ntop(a->addr, ip6str, sizeof(ip6str)));
                    break;
                default:
                    //printf("\tAddress Family Name: Unknown\n");
                    break;
            }
        }
        allDev.append(tempDevInfo);
    }
    pcap_freealldevs(alldevs);
    return allDev;
}
/*-----------------*/
//本机信息
/*-----------------*/
// 获取网卡Mac
void initdevinfo::getSelfMac(QString dev)
{
    memset(hostInfo.mac, 0, sizeof(hostInfo.mac));
    QByteArray pDevName = dev.toLatin1();

    LPADAPTER lpAdapter = PacketOpenAdapter(pDevName.data());

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        return;
    }

    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL)
    {
        PacketCloseAdapter(lpAdapter);
        return;
    }
    //
    // Retrieve the adapter MAC querying the NIC driver
    //
    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;
    memset(OidData->Data, 0, 6);
    BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);

    if (Status)
    {
        memcpy(hostInfo.mac, (u_char*)(OidData->Data), 6);
    }
    free(OidData);
    PacketCloseAdapter(lpAdapter);
}
// 设置所选网卡的信息：ip 、 掩码
void initdevinfo::setselectdevinfo(QString dev)
{
    for(int i = 0; i < devall->length(); ++i){
        if(dev==devall->at(i).name)
        {
            std::string str1 = devall->at(i).address.toStdString();
            const char* ch1 = str1.c_str();
            strcpy(hostInfo.ip,ch1);
            std::string str2 = devall->at(i).netmask.toStdString();
            const char* ch2 = str2.c_str();
            strcpy(hostInfo.netmask,ch2);

            return;
        }
    }
}

// 应用过滤规则
void initdevinfo::applyFilter(QString dev,QString rule)
{

    setselectdevinfo(dev);
    std::string str = dev.toStdString();
    filterThread = new FilterThread(&hostInfo,str.c_str(),rule);

    filterThread->start();
}
// 停止过滤
void initdevinfo::stopFilter()
{

    filterThread->getbuffp()->clear();

    if(filterThread->isRunning())
        filterThread->quitThread();

    filterThread=NULL;
}
QQueue< Package> * initdevinfo::transferbuffp()
{
    tmpbuffp = filterThread->getbuffp();
    return tmpbuffp;
}
QQueue< Package> * initdevinfo::opengumpfile(QString filename)
{
    tmpbuffp=new QQueue<Package>;
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    char timestr[16] = {0};
    time_t local_tv_sec;
    struct tm *ltime;

    std::string tmp = filename.toStdString();
    const char *name = tmp.c_str();

    /* 打开捕获文件 */
    if((fp = pcap_open_offline(name,			// name of the device
                             errbuf					// error buffer
                             )) == NULL)
    {
        return NULL;
    };

    /* 从文件获取数据包 */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
    {
        if(res == 0)
             /* 超时时间到 */
              continue;
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        QString usecs;
        usecs.sprintf("%06ld",header->ts.tv_usec);
        QString len = QString::number(header->len);
        Package getpackage;
        getpackage.time_s = QString(timestr);
        getpackage.time_us = usecs;
        memcpy(getpackage.data,pkt_data,header->len);
        getpackage.len = len;
        tmpbuffp->enqueue(getpackage);
    }
    return tmpbuffp;
}
//开始arp
void initdevinfo::arpStart(QString dev,QVector<QString> arp)
{
    setselectdevinfo(dev);
    getSelfMac(dev);
    if(arp.length()!=4){
        qDebug()<<"长度不够！";
        return;
    }
    ArpCheatpacket *arpinfo=new ArpCheatpacket();
    strcpy(arpinfo->sourIp,hostInfo.ip);
    std::string dip = arp.at(3).toStdString();
    strcpy(arpinfo->dstIp,dip.c_str());
    std::string gip = arp.at(1).toStdString();
    strcpy(arpinfo->gatewayIp,gip.c_str());

    memcpy(arpinfo->sourMac,hostInfo.mac,6);

    u_char gmac[6];
    u_char dmac[6];

    QStringList list1 = arp.at(0).split(":");
    for(int i = 0; i < list1.length(); ++i){
        gmac[i] = hexStr2UChar(list1.at(i));
    }

    QStringList list2 = arp.at(2).split(":");
    for(int i = 0; i < list2.length(); ++i){
        dmac[i] = hexStr2UChar(list2.at(i));
    }

    memcpy(arpinfo->dstMac,dmac,6);
    memcpy(arpinfo->gatewayMac,gmac,6);
    std::string str = dev.toStdString();
    usearp_p = new usearp(arpinfo, str.c_str());

    usearp_p->start();
}
// 停止arp
void initdevinfo::arpStop()
{
    if(usearp_p!=NULL){
        if(usearp_p->isRunning())
            usearp_p->quitThread();
        usearp_p=NULL;
        qDebug()<<"停止欺骗";
    }
}
u_char initdevinfo::hexStr2UChar(QString hexS)
{
    QByteArray array = hexS.toUtf8();
    char *data = array.data();
    char *str;
    u_char ret = (u_char)strtol(data,&str,16);
    //printf("%d %02x\n",ret,ret);
    return ret;
}
