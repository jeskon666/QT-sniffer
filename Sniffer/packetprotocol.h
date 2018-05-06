#ifndef PACKETPROTOCOL_H
#define PACKETPROTOCOL_H

#include "ethernet.h"
#include <QString>

//***********************************************************************************
//YEthernetPacket
//***********************************************************************************
class YEthernetPacket
{
public:
    YEthernetPacket();
    void setData(const u_char *Pdata);
    EthernetHeader getData();

    QString getEtherSrcMacAdd();
    QString getEtherDestMacAdd();
    u_short getEtherNetType();

    void fillEthernetHeader(u_char* srcMac, u_char* detMac, u_short type);
private:
    EthernetHeader data;
};

//***********************************************************************************
//YIPHeaderPacket Class
//***********************************************************************************
class YIPHeaderPacket
{
public:
    YIPHeaderPacket();

    void setData(const u_char *pktData);
    IPHeader getDate();

    QString getProtocolType();
    QString gettotallen();
    QString getSourceIpAddStr();
    QString getDestIpAddStr();
private:
    IPHeader data;
};

//***********************************************************************************
//YICMPHeaderPacket Class 关键是校验和生成
//***********************************************************************************
class YICMPHeaderPacket
{
public:
    YICMPHeaderPacket();
    void setData(const u_char *pktData);
    ICMPHeader getDate();
    QString getType();
    QString getCode();
    QString getchecksum();
    QString getident();
    QString getSeq();
    // 计算校验和
    //u_short calcCheckSum(u_short *icmpHeader,int headerLen);
    //

private:
    ICMPHeader data;
};

//***********************************************************************************
//YIGMPHeaderPacket
//***********************************************************************************
class YIGMPHeaderPacket
{
public:
    YIGMPHeaderPacket();
    void setData(const u_char *pktData);
    IGMPHeader getDate();

private:
    IGMPHeader data;
};


//***********************************************************************************
//YArpPacket Class
//***********************************************************************************
class YArpPacket
{
public:
    YArpPacket();
    void setData(const u_char *Pdata);

    ArpPacket* getData();
    void clearData();
    /* fillArpPacket 硬件len=6,协议len=4已默认 */
    void fillArpHeader(u_short hdType,u_short proType,u_short opFilt,
                       u_char *srcMac,char *srcIp,u_char *destMac,char *destIp);
    void fillArpEthernetHeader(u_char* srcMac, u_char* detMac);
    void fillArpfill();
    void fillArpcrc();
    u_short getEtherNetType();
    u_short getHardwareType();
    u_short getProtocolType();
    u_short getOperationField();
    QString getSourceMacAdd();
    QString getSourceIpAddStr();
    u_long getSourceIpAdd();
    QString getDestIpAddStr();
    u_long getDestIpAdd();
    QString getDestMacAdd();

    EthernetHeader getEthernetPacket();
private:
    ArpPacket data;
};

//***********************************************************************************
//YTcpPacket Class
//***********************************************************************************

class YTcpHeader
{
public:
    YTcpHeader();
    void setData(const u_char *pktData);
    TCPPacketHeader getData();
    QString getFlag();
    QString getSrcPort();
    QString getDstPort();
    QString getseqnum();
    QString getack();
    QString getchecksum();
    QString getlen();

private:
    TCPPacketHeader data;
    u_short calcCheckNum(u_short* buffer, int size);

};
class YUdpHeader
{
public:
    YUdpHeader();
    void setData(const u_char *pktData);
    UDPHeader getData();
    QString getSrcPort();
    QString getDstPort();
    QString getchecksum();
    QString getlen();

private:
    UDPHeader data;
};


#endif // PACKETPROTOCOL_H
