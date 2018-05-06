#-------------------------------------------------
#
# Project created by QtCreator 2018-04-12T19:46:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer_zsk
TEMPLATE = app
# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
INCLUDEPATH += E:\WpdPack\Include
LIBS += E:\WpdPack\Lib\libpacket.a
LIBS += E:\WpdPack\Lib\libwpcap.a
LIBS += E:\WpdPack\Lib\Packet.lib
LIBS += E:\WpdPack\Lib\wpcap.lib

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    #arp.cpp \
    #arp_attack.cpp \
    arpdialog.cpp \
    initdevinfo.cpp \
    filterthread.cpp \
    packetprotocol.cpp \
    usearp.cpp \
    httpdialog.cpp

HEADERS += \
        mainwindow.h \
    ethernet.h \
    arpdialog.h \
    initdevinfo.h \
    filterthread.h \
    packetprotocol.h \
    usearp.h \
    httpdialog.h

FORMS += \
        mainwindow.ui \
    arpdialog.ui \
    httpdialog.ui

RESOURCES += \
    res.qrc
