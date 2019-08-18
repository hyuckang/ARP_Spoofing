#pragma once
#include "init.h"

u_char* arp_request_maker(u_char* my_MACaddr, u_char* TargetIP);

u_char* arp_request_maker(u_char* my_MACaddr, u_char* TargetIP)
{

    arp_packet arp_request;
    u_char* request_buf = (u_char*) malloc(sizeof(arp_request));

    /* ether info */
    memcpy(arp_request.eth_hdr.src_addr, my_MACaddr, sizeof(u_char)*6);
    for(int i=0;i<6;i++) arp_request.eth_hdr.dst_addr[i] = 0xFF;
    arp_request.eth_hdr.ether_type = ntohs(ether_type_ARP);

    /* arp info */
    arp_request.arp_hdr.op_code = ntohs(ARP_Request);
    memcpy(arp_request.arp_hdr.send_hw_addr, my_MACaddr, sizeof(u_char)*6);
    for(int i=0;i<4;i++) arp_request.arp_hdr.send_ip_addr[i] = 0x00;

    memcpy(arp_request.arp_hdr.target_ip_addr, TargetIP, sizeof(u_char)*4);
    for(int i=0; i<6; i++) arp_request.arp_hdr.target_hw_addr[i] = 0x00;

    memcpy(request_buf, &arp_request, sizeof(arp_request));

    return request_buf;
}

