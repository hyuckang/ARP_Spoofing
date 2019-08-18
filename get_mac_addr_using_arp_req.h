#pragma once
#include "init.h"

void get_mac_addr_using_arp_req(pcap_t* handle, u_char* my_MACaddr, u_char* mac_addr_store, u_char* request_IP);

void get_mac_addr_using_arp_req(pcap_t* handle, u_char* my_MACaddr, u_char* mac_addr_store, u_char* request_IP)
{

    /* arp request packet make */
    u_char* request_buf = arp_request_maker(my_MACaddr, request_IP);
    arp_packet arp_packet_getMAC;

    /* arp request send and get mac addr in arp reply */
    struct pcap_pkthdr* header;
    const u_char* packet;

    while(true)
    {
        int res = pcap_sendpacket(handle, request_buf, 42);
        if(res == -1) printf("Send ARP Request Packet Error\n");
        else printf("Send ARP Request Packet Sucsess\n");

        pcap_next_ex(handle, &header, &packet);
        memcpy(&arp_packet_getMAC, packet, sizeof(arp_packet_getMAC));

        if( ntohs(arp_packet_getMAC.eth_hdr.ether_type) == ether_type_ARP
                && ntohs(arp_packet_getMAC.arp_hdr.op_code) == ARP_Replay
                && arp_packet_getMAC.arp_hdr.send_ip_addr[0] == request_IP[0]
                && arp_packet_getMAC.arp_hdr.send_ip_addr[1] == request_IP[1]
                && arp_packet_getMAC.arp_hdr.send_ip_addr[2] == request_IP[2]
                && arp_packet_getMAC.arp_hdr.send_ip_addr[3] == request_IP[3]
                && arp_packet_getMAC.arp_hdr.target_ip_addr[0] == 0x00
                && arp_packet_getMAC.arp_hdr.target_ip_addr[1] == 0x00
                && arp_packet_getMAC.arp_hdr.target_ip_addr[2] == 0x00
                && arp_packet_getMAC.arp_hdr.target_ip_addr[3] == 0x00)
        {
            memcpy(mac_addr_store, arp_packet_getMAC.eth_hdr.src_addr, sizeof(u_char) * 6);
            free(request_buf);
            break;
        }
        sleep(1);
    }
    return;
}
