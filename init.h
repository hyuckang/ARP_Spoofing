#pragma once

#include <iostream>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <thread>
#include <vector>

struct session
{
    char* dev;
    pcap_t* handle;
    u_char attackerMAC[6];
    u_char senderIP[4];
    u_char senderMAC[6];
    u_char targetIP[4];
    u_char targetMAC[6];

};

#include "print_func.h"
#include "ethernet_header.h"
#include "arp_packet_format.h"
#include "ipv4_header.h"
#include "get_my_mac_addr.h"
#include "arp_request_maker.h"
#include "arp_reply_maker.h"
#include "get_mac_addr_using_arp_req.h"
#include "send_arp_reply.h"
#include "arp_spoof.h"
