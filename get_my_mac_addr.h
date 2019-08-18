/* Reference : https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
#pragma once
#include "init.h"

/* return my MAC Address */
void get_my_mac_addr(char* interface_name, u_char* store_mac_address_array);

void get_my_mac_addr(char* interface, u_char* mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;

    /* interface name copy  */
    int if_name_size = strlen(interface);
    strncpy(ifr.ifr_name, interface, if_name_size+1);

    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));


    for (; it != end; ++it) {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    /* Copy the mac address of a specific interface */
    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, sizeof(u_char)*6);

    return;
}
