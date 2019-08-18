#pragma once
#include "init.h"

#define ETHER_ADDR_LEN   6
#define IP_ADDR_LEN 4
#define ARP_HTYPE_ETHER 0x0100  /* Ethernet ARP type */
#define ARP_PTYPE_IPv4 0x0008   /* IPv4 */
#define ARP_HW_SIZE 0x06
#define ARP_PROTOCOL_SIZE 0x04
#define ARP_TARGET_IP 0x00000000
#define ARP_Request 0x0001
#define ARP_Replay 0x0002

typedef struct {

    uint16_t hw_type = ARP_HTYPE_ETHER;         /* Format of hardware address */
    uint16_t protocol_type = ARP_PTYPE_IPv4;    /* Format of protocol address */
    uint8_t hw_addr_len = ARP_HW_SIZE;          /* Length of hardware address */
    uint8_t proto_add_len = ARP_PROTOCOL_SIZE;  /* Length of protocol address */
    uint16_t op_code;                           /* ARP opcode */
    uint8_t send_hw_addr[ETHER_ADDR_LEN];       /* Sender hardware address */
    uint8_t send_ip_addr[IP_ADDR_LEN];          /* Sender IP address */
    uint8_t target_hw_addr[ETHER_ADDR_LEN];     /* Target hardware address */
    uint8_t target_ip_addr[IP_ADDR_LEN];        /* Target IP address */
} arp_ether_ipv4;

typedef struct {
    ETHER_HEADER eth_hdr;
    arp_ether_ipv4 arp_hdr;
}arp_packet;
