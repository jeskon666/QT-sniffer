// ---------------------------------------------
// TCP/IP基础结构体和通用函数
// ---------------------------------------------
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <QString>

typedef unsigned char       u_char;
typedef unsigned short int  u_short;
typedef unsigned int        u_int;
typedef unsigned long       u_long;


// Ethernet
#define ETHERNET_HEAD_LENGTH    14
#define ARP_TYPE            0x0806          //以太头类型：ARP类型,地址解析协议
#define IP_TYPE             0x0800          //以太头类型：IPV4类型,	网际协议版本4
#define IPV6_TYPE           0x86dd          //以太头类型，IPV6类型,网际协议版本6
#define MAX_MTU             1600
//
// ARP Body 28bytes
// ARP Packet(42bytes) = Ethernet(14bytes) + ARP Body(28bytes)
#define ARP_BODY_LENGTH         28
#define ARP_PACKET_LENGTH       42
#define ARP_FILL_LENGTH         18
#define ARP_CRC_LENGTH           4
#define MPLS_TYPE           0x8847
#define IPX_TYPE            0x8137
#define IS_IS_TYPE          0x8000
#define LACP_TYPE           0x8809
#define _802_1x_TYPE        0x888E
#define ARP_HARDWARE        0x0001          //ARP包中：以太网
#define ARP_REQUEST         0x0001
#define ARP_REPLY           0x0002

// IP Header 20bytes
#define IP_HEAD_LENGTH       20
#define IP_HEAD_WITH_ETHERNET_LENGTH 34
#define IP_VERSION_4        0x04            //IPV4头，版本4
#define IP_VERSION_6        0x06            //IPV4头，版本6

#define IP_TCP_TYPE         0x06            //IPV4头中的协议类型：TCP
#define IP_UDP_TYPE         0x11            //IPV4头中的协议类型：UDP
#define IP_ICMP_TYPE        0x01            //IPV4头中的协议类型：ICMP
#define IP_IGMP_TYPE        0x02            //IPV4头中的协议类型：IGMP

// ICMP
#define ICMP_HEAD_LENGTH    8
#define ICMP_ECHO_REPLAY    0x00
#define ICMP_ECHO_REQUEST   0x08

// IGMP
#define IGMP_HEAD_LENGTH    8

// TCP Header 20bytes
#define TCP_HEAD_LENGTH         20
#define TCP_PACKET_LENGTH       54          // ethernetheader(14) + ipheader(20) + tcpheader(20)
#define TCP_SYN             0x6002          // 握手：SYN
#define TCP_SYN_ACK         0x12            // 握手应答：SYN_ACK
#define TCP_RST_ACK         0x14            // 拒绝应答：RST_ACK
#define TCP_RST             0x5004          // 拒绝链接：RST
//UDP
#define UDP_HEAD_LENGTH       8
#define UDP_PACKET_LENGTH     42


//***********************************************************************************
//常用网络协议自定义结构体
//***********************************************************************************
// Ethernet addresses are 6 bytes
typedef struct _DEVInfo{
    QString name;
    QString description;
    QString familyName;         //协议族，
    QString address;            //主机ip
    QString netmask;            //子网掩码
}DEVInfo;
#define ETHER_ADDR_LEN 6
typedef struct _EthernetHeader
{
    u_char DestMAC[ETHER_ADDR_LEN];          //目的MAC地址 6字节
    u_char SourMAC[ETHER_ADDR_LEN];          //源MAC地址 6字节
    u_short EthType;                         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
}EthernetHeader;

// 4 bytes IP address
typedef struct _IPAddress{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}IPAddress;
typedef struct _PACKAGE{
    QString time_s;
    QString time_us;
    //const u_char * data;
    u_char data[MAX_MTU];
    QString len;
}Package;
// IPv4 header 20bytes
typedef struct _IpHeader{
    u_char	VerIhl;         // 版本4 + 首部长度4Version (4 bits) + Internet header length (4 bits)
    u_char	Tos;			// 服务类型Type of service
    u_short Tlen;			// 总长度Total length，包括IP20字节的头
    u_short Identification; // 标识Identification
    u_short FlagsFo;		// 标志(4 bits)+片偏移(12 bits)Flags (3 bits) + Fragment offset (13 bits)
    u_char	Ttl;			// 生存时间Time to live
    u_char	Proto;			// 协议类型：TCP(6)、UDP(17)、ICMP(1)
    u_short Crc;			// 首部校验和Header checksum
    u_char SourceIpAdd[4];	// 源地址Source address
    u_char DestIpAdd[4];	// 目标地址Destination address
}IPHeader;

// ICMP
typedef struct _ICMPHeader{
    u_char type;            // reply:0 ,request:8
    u_char code;            // 代码
    u_short checkSum;       // 校验和
    u_short ident;          //
    u_short seq;            // 序列号
    //u_char data[32];      //可变长度
}ICMPHeader;

// IGMP
typedef struct _IGMPHeader{
    u_char ver_type;  //版本和类型
    u_char not_use;   //未使用
    u_short checkSum;    //校验和
    u_long groupip;           //D类IP
}IGMPHeader;
// TCP数据包的头部 20 bytes
typedef struct _TCPPacketHeader {
    u_short	SrcPort;		//源端口
    u_short	DestPort;		//目的端口
    u_long	Seq;			//序列号
    u_long	Ack;			//确认序列号
    //u_short	Lenres;			//数据偏移4+保留区6+URG+ACK+PSH+RST+SYN+FIN,可以将u_short分为两个u_char
    u_char len;             //（数据偏移）TCP首部长度，仅4bit，后4bit必须为零
    u_char flags;           //前2bit为零，后面各位是URG,ACK,PSH,RST,SYN,FIN
    u_short	Win;			//窗口大小
    u_short	Sum;			//校验和
    u_short	Urp;			//紧急指针
}TCPPacketHeader;

// 12字节的TCP伪首部，参与校验和计算
typedef struct _PsedoTCPHead{
    u_char  source_addr[4];
    u_char  dest_addr[4];
    u_char  zero;
    u_char  protocol;
    u_short seg_len;
}PsedoTCPHead;

// UDP header
typedef struct _UDPHeader{
    u_short SrcPort;		// Source port
    u_short DestPort;		// Destination port
    u_short Len;			// Datagram length
    u_short Crc;			// Checksum
}UDPHeader;


// 28 bytes ARP request/reply
typedef struct _ArpHeader {
    u_short HardwareType;          //硬件类型,2字节，定义运行ARP的网络的类型，以太网是类型1
    u_short ProtocolType;          //协议类型,2字节，定义上层协议类型，对于IPV4协议，该字段值为0800
    u_char HardwareAddLen;         //硬件地址长度,8位字段，定义对应物理地址长度，以太网中这个值为6
    u_char ProtocolAddLen;         //协议地址长度,8位字段，定义以字节为单位的逻辑地址长度，对IPV4协议这个值为4
    u_short OperationField;        //操作字段,数据包类型,ARP请求（值为1），或者ARP应答（值为2）
    u_char SourceMacAdd[6];        //源（发送端）mac地址,可变长度字段，对以太网这个字段是6字节长
    u_char SourceIpAdd[4];         //源（发送短）ip地址,发送端协议地址，可变长度字段，对IP协议，这个字段是4字节长
    u_char DestMacAdd[6];          //目的（接收端）mac地址
    u_char DestIpAdd[4];           //目的（接收端）ip地址,注意不能为u_int型，结构体对其
}ArpHeader;

//arp packet = 14 bytes ethernet header + 28 bytes request/reply
typedef struct _ArpPacket {
    EthernetHeader ed;
    ArpHeader ah;
    u_char fill[18];
    u_char crc[4];
}ArpPacket;

// host infomation
typedef struct _HostInfo{
    u_char mac[6];
    char ip[16];
    char netmask[16];
}HostInfo;
typedef struct _GatewayInfo{
    char gatewayIp[16];
    u_char gatewayMac[6];
}GatewayInfo;
typedef struct _ArpCheatpacket{
    char sourIp[16];
    u_char sourMac[6];
    char dstIp[16];
    u_char dstMac[6];
    char gatewayIp[16];
    u_char gatewayMac[6];
}ArpCheatpacket;
//***********************************************************************************
//网络常用转换函数声明和说明
//***********************************************************************************
//my_htonl函数，本机字节序转网络字节序(32位字节序)
//my_ntohl函数，网络字节序转本机字节序(32位字节序)
//my_htons函数，本机字节序转网络字节序(16位字节序)
//my_ntohs函数，网络字节序转本机字节序(16位字节序)
//my_iptos函数，将字节序ip地址转为点分十进制的字符串地址
//iptos   函数，将字节序ip地址转为点分十进制的字符串地址,并获取
//my_inet_addr

// 本机大端返回1，小端返回0
inline int checkCPUendian();

// 模拟htonl函数，本机字节序转网络字节序
inline u_long my_htonl(u_long h);
// 模拟ntohl函数，网络字节序转本机字节序
inline u_long my_ntohl(u_long n);

// 模拟htons函数，本机字节序转网络字节序
inline u_short my_htons(u_short h);

// 模拟ntohs函数，网络字节序转本机字节序
inline u_short my_ntohs(u_short n);

// 数字类型的IP地址转换成点分十进制字符串类型的
//inline char *iptos(u_long in,char * ipStr);

// 将字节序ip地址转为点分十进制的字符串地址,并获取
inline char *my_iptos(u_long in);

// 将点分十进制的字符串地址转网络字节整形
inline u_int my_inet_addr(const char *ptr);


//***********************************************************************************
//网络常用转换函数和宏集
//***********************************************************************************

// 短整型大小端互换
#define BigLittleSwap16(A)  ((((u_short)(A) & 0xff00) >> 8) | \
                            (((u_short)(A) & 0x00ff) << 8))
// 长整型大小端互换
#define BigLittleSwap32(A)  ((((u_long)(A) & 0xff000000) >> 24) | \
                            (((u_long)(A) & 0x00ff0000) >> 8) | \
                            (((u_long)(A) & 0x0000ff00) << 8) | \
                            (((u_long)(A) & 0x000000ff) << 24))

// 本机大端返回1，小端返回0
int checkCPUendian()
{
    union{
          u_long i;
          u_char s[4];
    }c;

    c.i = 0x12345678;
    return (0x12 == c.s[0]);
}

// 模拟htonl函数，本机字节序转网络字节序
u_long my_htonl(u_long h)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，转换成大端再返回
    return checkCPUendian() ? h : BigLittleSwap32(h);
}

// 模拟ntohl函数，网络字节序转本机字节序
u_long my_ntohl(u_long n)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，网络数据转换成小端再返回
    return checkCPUendian() ? n : BigLittleSwap32(n);
}

// 模拟htons函数，本机字节序转网络字节序
u_short my_htons(u_short h)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，转换成大端再返回
    return checkCPUendian() ? h : BigLittleSwap16(h);
}

// 模拟ntohs函数，网络字节序转本机字节序
u_short my_ntohs(u_short n)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，网络数据转换成小端再返回
    return checkCPUendian() ? n : BigLittleSwap16(n);
}

// 数字类型的IP地址转换成点分十进制字符串类型的
/*char *iptos(u_long in,char * ipStr)
{
    u_char *p;
    p = (u_char *)&in;
    sprintf(ipStr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return ipStr;
}*/

#define IPTOSBUFFERS    12
char *my_iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/*char* my_ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}*/
//点分ip转数
u_int my_inet_addr(const char *ptr)
{
    int a[4],i=0;
    char str[255] = {0};
    u_long num;

    strcpy(str,ptr);
    char *p1=str,*p2,*p3;
    while(*p1!='\0' && i<4 ){
        p2=strstr(p1,".");
        if(i!=3){
            p3=p2+1;
            *p2='\0';
        }
        a[i] = atoi(p1);
        if(a[i]<0 || a[i]>255){
            printf("Invalid IP address!\n");
            exit(1);
        }
        p1=p3;
        i++;
     }
     num=a[0]*256*256*256+a[1]*256*256+a[2]*256+a[3];
     return num;
}

#endif // ETHERNET_H
