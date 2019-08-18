#pragma once
#include "init.h"

void printMAC(char* commnet, u_char* MACaddr);
void printIP(char* comment, u_char* IPaddr);
void usage();

void usage()
{
    printf("syntax error!\n");
    printf("syntax : arp_spoof <interface> <sender ip1> <target ip2> <sender ip2> <target ip2>\n");
    printf("example : arp_spoof eth0 192.168.10.5 192.168.10.1 192.168.10.1 192.168.10.1 192.168.10.5\n");
    return;
}

void printMAC(char* commnet, u_char* MACaddr)
{
    printf("%s : %2x:%2x:%2x:%2x:%2x:%2x\n", commnet , *MACaddr, *(MACaddr+1), *(MACaddr+2), *(MACaddr+3), *(MACaddr+4), *(MACaddr+5));
    return;
}

void printIP(char* comment, u_char* IPaddr){
    printf("%s : %3d.%3d.%3d.%3d\n", comment, *IPaddr, *(IPaddr+1), *(IPaddr+2), *(IPaddr+3));
    return;
}
