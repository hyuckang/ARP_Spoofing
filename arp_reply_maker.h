#pragma once
#include "init.h"


u_char* arp_reply_maker(u_char* my_MACaddr, u_char* senderIP, u_char* targetMAC, u_char* targetIP);

u_char* arp_reply_maker(u_char* my_MACaddr, u_char* senderIP, u_char* targetMAC, u_char* targetIP){

    arp_packet arp_reply;
    u_char* packetbuf = (u_char*) malloc(sizeof(arp_reply));

    /* ether info */
    memcpy(arp_reply.eth_hdr.dst_addr, targetMAC, sizeof(u_char)*6);
    memcpy(arp_reply.eth_hdr.src_addr, my_MACaddr, sizeof(u_char)*6);
    arp_reply.eth_hdr.ether_type = ntohs(ether_type_ARP);

    /* arp info */
    arp_reply.arp_hdr.op_code = ntohs(ARP_Replay);
    memcpy(arp_reply.arp_hdr.send_hw_addr, my_MACaddr, sizeof(u_char)*6);
    memcpy(arp_reply.arp_hdr.send_ip_addr, senderIP, sizeof(u_char)*4);

    memcpy(arp_reply.arp_hdr.target_hw_addr, targetMAC, sizeof(u_char)*6);
    memcpy(arp_reply.arp_hdr.target_ip_addr, targetIP, sizeof(u_char)*4);


    printf("=== ARP Reply packet info ===\n");
    printf("eth dst_addr : %2x:%2x:%2x:%2x:%2x:%2x\n",arp_reply.eth_hdr.dst_addr[0],arp_reply.eth_hdr.dst_addr[1],arp_reply.eth_hdr.dst_addr[2],
            arp_reply.eth_hdr.dst_addr[3],arp_reply.eth_hdr.dst_addr[4],arp_reply.eth_hdr.dst_addr[5]);

    printf("eth src addr : %2x:%2x:%2x:%2x:%2x:%2x\n",arp_reply.eth_hdr.src_addr[0],arp_reply.eth_hdr.src_addr[1],arp_reply.eth_hdr.src_addr[2],
            arp_reply.eth_hdr.src_addr[3],arp_reply.eth_hdr.src_addr[4],arp_reply.eth_hdr.src_addr[5]);

    printf("send_hw_addr : %2x:%2x:%2x:%2x:%2x:%2x\n",arp_reply.arp_hdr.send_hw_addr[0], arp_reply.arp_hdr.send_hw_addr[1],arp_reply.arp_hdr.send_hw_addr[2],
            arp_reply.arp_hdr.send_hw_addr[3], arp_reply.arp_hdr.send_hw_addr[4], arp_reply.arp_hdr.send_hw_addr[5]);

    printf("send_ip_addr : %2d:%2d:%2d:%2d\n",arp_reply.arp_hdr.send_ip_addr[0], arp_reply.arp_hdr.send_ip_addr[1],
            arp_reply.arp_hdr.send_ip_addr[2], arp_reply.arp_hdr.send_ip_addr[3]);

    printf("target_hw_addr : %2x:%2x:%2x:%2x:%2x:%2x\n",arp_reply.arp_hdr.target_hw_addr[0],arp_reply.arp_hdr.target_hw_addr[1],
            arp_reply.arp_hdr.target_hw_addr[2], arp_reply.arp_hdr.target_hw_addr[3], arp_reply.arp_hdr.target_hw_addr[4], arp_reply.arp_hdr.target_hw_addr[5]);

    printf("target_ip_addr : %2d:%2d:%2d:%2d\n",arp_reply.arp_hdr.target_ip_addr[0], arp_reply.arp_hdr.target_ip_addr[1],
            arp_reply.arp_hdr.target_ip_addr[2], arp_reply.arp_hdr.target_ip_addr[3]);

    printf("\n");

    memcpy(packetbuf, &arp_reply, sizeof(arp_reply));

    return packetbuf;
}

