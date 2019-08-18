TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread

SOURCES += main.cpp

HEADERS += \
    init.h \
    get_my_mac_addr.h \
    ethernet_header.h \
    arp_request_maker.h \
    arp_packet_format.h \
    arp_reply_maker.h \
    get_mac_addr_using_arp_req.h \
    print_func.h \
    arp_spoof.h \
    ipv4_header.h \
    send_arp_reply.h

PRECOMPILED_HEADER = init.h
