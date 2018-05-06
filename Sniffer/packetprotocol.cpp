#include "packetprotocol.h"

//***********************************************************************************
//EthernetPacket 14字节
//***********************************************************************************
YEthernetPacket::YEthernetPacket()
{
    memset(&data,0,ETHERNET_HEAD_LENGTH);
}

void YEthernetPacket::fillEthernetHeader(u_char* srcMac, u_char* detMac, u_short type)
{
    memset(&data,0,ETHERNET_HEAD_LENGTH);
    EthernetHeader* ethHdr = &data;

    memcpy(ethHdr->SourMAC, srcMac, sizeof(u_char) * 6);
    memcpy(ethHdr->DestMAC, detMac, sizeof(u_char) * 6);
    ethHdr->EthType = my_htons(type);
}

EthernetHeader YEthernetPacket::getData()
{
    return data;
}

QString YEthernetPacket::getEtherSrcMacAdd()
{
    QString macBuf;
    macBuf.sprintf("%02x:%02x:%02x:%02x:%02x:%02x",data.SourMAC[0],data.SourMAC[1],data.SourMAC[2],data.SourMAC[3], data.SourMAC[4], data.SourMAC[5]);
    return macBuf;
}

QString YEthernetPacket::getEtherDestMacAdd()
{
    char macBuf[64] = {0};
    sprintf(macBuf,"%02x:%02x:%02x:%02x:%02x:%02x",data.DestMAC[0],data.DestMAC[1],data.DestMAC[2],data.DestMAC[3], data.DestMAC[4], data.DestMAC[5]);
    return QString(macBuf);
}

//判断是ARP包或者是IP包
u_short YEthernetPacket::getEtherNetType()
{
    u_short etherType = data.EthType;
    return etherType;
}

void YEthernetPacket::setData(const u_char *Pdata)
{
    memcpy(&data,Pdata,ETHERNET_HEAD_LENGTH);
}

//***********************************************************************************
//YIPHeaderPacket 20字节
//***********************************************************************************
YIPHeaderPacket::YIPHeaderPacket()
{
    memset(&data,0,IP_HEAD_LENGTH);
}

void YIPHeaderPacket::setData(const u_char *pktData)
{
    memcpy(&data,pktData+14,IP_HEAD_LENGTH);
}
IPHeader YIPHeaderPacket::getDate()
{
    return data;
}
QString YIPHeaderPacket::getProtocolType()
{
    u_char protocolType = data.Proto;

    if(protocolType == (IP_TCP_TYPE)){
        return "TCP";
    }
    else if(protocolType == (IP_UDP_TYPE)){
        return "UDP";
    }
    else if(protocolType == (IP_ICMP_TYPE)){
        return "ICMP";
    }
    else if(protocolType == (IP_IGMP_TYPE)){
        return "IGMP";
    }
    else return "UNKNOWN";
}
QString YIPHeaderPacket::gettotallen()
{
    QString len;
    return len.sprintf("%d",my_ntohs(data.Tlen));
}
QString YIPHeaderPacket::getSourceIpAddStr()
{
    u_long ipN;
    memcpy(&ipN,data.SourceIpAdd,sizeof(u_char)*4);
    char *str = my_iptos(ipN);
    return QString(str);
}

QString YIPHeaderPacket::getDestIpAddStr()
{

    u_long ipN;
    memcpy(&ipN,data.DestIpAdd,sizeof(u_char)*4);
    char *str = my_iptos(ipN);
    return QString(str);
}
//***********************************************************************************
//YICMPHeaderPacket 只需要ICMP头即可 8字节
//***********************************************************************************
YICMPHeaderPacket::YICMPHeaderPacket()
{
    memset(&data,0,ICMP_HEAD_LENGTH);
}
void YICMPHeaderPacket::setData(const u_char *pktData)
{
    memcpy(&data,pktData+34,ICMP_HEAD_LENGTH);
}
ICMPHeader YICMPHeaderPacket::getDate()
{
    return data;
}
QString YICMPHeaderPacket::getType()
{
    QString tmp;
    return tmp.sprintf("%d",data.type);
}
QString YICMPHeaderPacket::getCode()
{
    QString tmp;
    return tmp.sprintf("%d",data.code);
}
QString YICMPHeaderPacket::getchecksum()
{
    QString tmp;
    return tmp.sprintf("%04x",my_ntohs(data.checkSum));
}
QString YICMPHeaderPacket::getident()
{
    QString tmp;
    return tmp.sprintf("%04x",my_ntohs(data.ident));
}
QString YICMPHeaderPacket::getSeq()
{
    QString tmp;
    return tmp.sprintf("%04x",my_ntohs(data.seq));
}
/*u_short YICMPHeaderPacket::calcCheckSum(u_short *icmpHeader,int headerLen)
{
    int nleft = headerLen;
    int sum = 0;
    unsigned short* w = icmpHeader;
    unsigned short answer = 0;

    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }

    if(nleft == 1){
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff); //高16位 + 低16位
    sum += (sum >> 16);                 //+进位
    answer = ~sum;                      //取反

    return (answer);
}*/
//***********************************************************************************
//YIGMPHeaderPacket
//***********************************************************************************
YIGMPHeaderPacket::YIGMPHeaderPacket()
{
    memset(&data,0,IGMP_HEAD_LENGTH);
}
void YIGMPHeaderPacket::setData(const u_char *pktData)
{
    memcpy(&data,pktData+34,IGMP_HEAD_LENGTH);
}
IGMPHeader YIGMPHeaderPacket::getDate()
{
    return data;
}

//***********************************************************************************
//ArpPacket
//***********************************************************************************
YArpPacket::YArpPacket()
{
    memset(&data,0,ARP_PACKET_LENGTH+ARP_FILL_LENGTH+ARP_CRC_LENGTH);
}
void YArpPacket::setData(const u_char *Pdata)
{
    memcpy(&data,Pdata,ARP_PACKET_LENGTH+ARP_FILL_LENGTH+ARP_CRC_LENGTH);
}
void YArpPacket::clearData()
{
    memset(&data,0,ARP_PACKET_LENGTH+ARP_FILL_LENGTH+ARP_CRC_LENGTH);
}

ArpPacket* YArpPacket::getData()
{
    return &data;
}

EthernetHeader YArpPacket::getEthernetPacket()
{
    return data.ed;
}

// fillArpPacket 硬件len=6,协议len=4已默认
void YArpPacket::fillArpHeader(u_short hdType,u_short proType,u_short opFilt,
                   u_char* srcMac,char *srcIp,u_char *destMac,char *destIp)
{
    memset(&data.ah,0,ARP_BODY_LENGTH);
    data.ah.HardwareAddLen = 6;
    data.ah.ProtocolAddLen = 4;

    data.ah.HardwareType = my_htons(hdType);
    data.ah.ProtocolType = my_htons(proType);
    data.ah.OperationField = my_htons(opFilt);
    memcpy(data.ah.SourceMacAdd, srcMac, 6);
    memcpy(data.ah.DestMacAdd, destMac, 6);
    u_long srcIpN = my_htonl(my_inet_addr(srcIp));
    memcpy(data.ah.SourceIpAdd,(u_char*)&srcIpN,4);
    u_long destIpN = my_htonl(my_inet_addr(destIp));
    memcpy(data.ah.DestIpAdd,(u_char*)&destIpN,4);
}
void YArpPacket::fillArpEthernetHeader(u_char* srcMac, u_char* detMac)
{
    memset(&data.ed,0,ETHERNET_HEAD_LENGTH);
    EthernetHeader* ethHdr = &data.ed;

    memcpy(ethHdr->SourMAC, srcMac, sizeof(u_char) * 6);
    memcpy(ethHdr->DestMAC, detMac, sizeof(u_char) * 6);
    ethHdr->EthType = my_htons(ARP_TYPE);
}
void YArpPacket::fillArpfill()
{
    memset(data.fill,0,ARP_FILL_LENGTH);
}
void YArpPacket::fillArpcrc()
{
    memset(data.crc,0,ARP_CRC_LENGTH);
}
u_short YArpPacket::getEtherNetType()
{
    u_short etherType = data.ed.EthType;
    return etherType;
}

u_short YArpPacket::getHardwareType()
{
    return data.ah.HardwareType;
}

u_short YArpPacket::getProtocolType()
{
    return data.ah.ProtocolType;
}

u_short YArpPacket::getOperationField()
{
    u_short opFiled = data.ah.OperationField;
    return opFiled;
}

QString YArpPacket::getSourceMacAdd()
{
    //u_char mac[6] = {0};
    char macBuf[64] = {0};
    //for (int i = 0; i < 6; i++) {
    //    mac[i] = *(unsigned char *) (data + 22 + i);
    //}
    sprintf(macBuf,"%02x:%02x:%02x:%02x:%02x:%02x",data.ah.SourceMacAdd[0],data.ah.SourceMacAdd[1],data.ah.SourceMacAdd[2],data.ah.SourceMacAdd[3], data.ah.SourceMacAdd[4], data.ah.SourceMacAdd[5]);
    return QString(macBuf);
}

u_long YArpPacket::getSourceIpAdd()
{
    u_long ipN;
    memcpy(&ipN ,data.ah.SourceIpAdd,4*sizeof(u_char));
    return ipN;
}

QString YArpPacket::getSourceIpAddStr()
{
    u_long ipN = getSourceIpAdd();
    char *str = my_iptos(ipN);
    return QString(str);
}

QString YArpPacket::getDestMacAdd()
{
    char macBuf[64] = {0};
    sprintf(macBuf,"%02x:%02x:%02x:%02x:%02x:%02x",data.ah.DestMacAdd[0],data.ah.DestMacAdd[1],data.ah.DestMacAdd[2],data.ah.DestMacAdd[3],data.ah.DestMacAdd[4], data.ah.DestMacAdd[5]);
    return QString(macBuf);
}

QString YArpPacket::getDestIpAddStr()
{
    u_long ipN = getDestIpAdd();
    char *str = my_iptos(ipN);
    return QString(str);
}

u_long YArpPacket::getDestIpAdd()
{
    u_long ipN;
    memcpy(&ipN,data.ah.DestIpAdd,4*sizeof(u_char));
    return ipN;
}

//***********************************************************************************
//YTcpPacket Class
//***********************************************************************************
YTcpHeader::YTcpHeader()
{
    memset(&data,0,TCP_HEAD_LENGTH);
}

/*u_short YTcpHeader::calcCheckNum(u_short* buffer, int size)
{
    u_long cksum = 0;
    while(size > 1){
        cksum += *buffer++;
        size -= sizeof(u_short);                //按双字节（16位）对齐
    }
    if(size){
        cksum += *(u_char*)buffer;             //二进制反码求和
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);//将高16bit与低16bit相加
    cksum += (cksum >> 16);                  //将进位到高位的16bit与低16bit 再相加
    return (u_short)(~cksum);
}*/

void YTcpHeader::setData(const u_char *pktData)
{
    memcpy(&data,pktData+34,TCP_HEAD_LENGTH);
}

TCPPacketHeader YTcpHeader::getData()
{
    return data;
}

QString YTcpHeader::getSrcPort()
{
    QString tmp;
    return tmp.sprintf("%hu",my_ntohs(data.SrcPort));
}
QString YTcpHeader::getFlag()
{
    QString tmp;
    return tmp.sprintf("%02x",data.flags);
}
QString YTcpHeader::getDstPort()
{
    QString tmp;
    return tmp.sprintf("%hu",my_ntohs(data.DestPort));
}
QString YTcpHeader::getseqnum()
{
    QString tmp;
    return tmp.sprintf("%lu",my_ntohl(data.Seq));
}
QString YTcpHeader::getack()
{
    QString tmp;
    return tmp.sprintf("%lu",my_ntohl(data.Ack));
}
QString YTcpHeader::getchecksum()
{
    QString tmp;
    return tmp.sprintf("%04x",my_ntohs(data.Sum));
}
QString YTcpHeader::getlen()
{
    QString tmp;
    return tmp.sprintf("%hu",4*(data.len>>4));
}
YUdpHeader::YUdpHeader()
{
    memset(&data,0,UDP_HEAD_LENGTH);
}
void YUdpHeader::setData(const u_char *pktData)
{
    memcpy(&data,pktData+34,UDP_HEAD_LENGTH);
}
UDPHeader YUdpHeader::getData()
{
    return data;
}
QString YUdpHeader::getSrcPort()
{
    QString tmp;
    return tmp.sprintf("%hu",my_ntohs(data.SrcPort));
}
QString YUdpHeader::getDstPort()
{
    QString tmp;
    return tmp.sprintf("%hu",my_ntohs(data.DestPort));
}
QString YUdpHeader::getlen()
{
    QString tmp;
    return tmp.sprintf("%hu",my_ntohs(data.Len));
}
QString YUdpHeader::getchecksum()
{
    QString tmp;
    return tmp.sprintf("%04x",my_ntohs(data.Crc));
}
