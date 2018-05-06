#ifndef USEARP_H
#define USEARP_H

#include <QThread>
#include "packetprotocol.h"
#include "pcap.h"

class usearp : public QThread
{

public:
    usearp(ArpCheatpacket *arpinfo, const char*dev);
    void quitThread();
    void sendArpCheatPacket();
    void run();

private:
    pcap_t * handle;
    ArpCheatpacket *arpinfo;
    YArpPacket *arppacket1;
    YArpPacket *arppacket2;
    bool quitFg;
};

#endif // USEARP_H
