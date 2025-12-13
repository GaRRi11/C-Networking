## arp-request

This process manually crafts an ARP request packet by building the ARP header and Ethernet header in user space and then injects the raw Ethernet frame directly onto the LAN, bypassing the kernel’s network stack.

types:
one used for checking dublicates, sent after dhcp provides ip. second is normal arp for finding neighbors for example router.

| Field              | Uniqueness Check (DAD-like) | Neighbor Discovery          |
| ------------------ | --------------------------- | --------------------------- |
| Sender IP          | `0.0.0.0`                   | Real IP (e.g. 192.168.1.10) |
| Sender MAC         | All zeros                   | Real MAC                    |
| Target IP          | IP being tested             | Neighbor IP                 |
| Purpose            | Detect duplicate IP         | Resolve MAC address         |


## 1. Create buffer which will be used to put error message in it if it occurs.

char errbuf[LIBNET_ERRBUF_SIZE];


## 2. Create object of libnet_t which will hold infos about:

interface info

injection method

internal packet buffer


libnet_t *l;

## 3. Create object of libnet_ptag_t, arp_tag.

Each call to libnet_build_* returns a tag.
Tags tell libnet which headers exist and in what order.

libnet_ptag_t arp_tag;


## 4. Create object of libnet_ptag_t, eth_tag.

Used for Ethernet header.
Each call to libnet_build_* returns tag, tags tell libnet which headers exist and in what order.

libnet_ptag_t eth_tag;


## 5. Initialize libnet in link layer injection mode.

Ethernet frames will be constructed manually.
Kernel will not touch L2.
Arguments given:

injection type

interface name

buffer needed for putting error in

l = libnet_init(
        LIBNET_LINK,  /* Injection type: Ethernet */
        argv[1],      /* Network interface name */
        errbuf        /* Error buffer */
    );


## 6. Create uint8_t variable which will hold our src_mac.

uint8_t src_mac[6] = {
    0x02, 0x11, 0x22, 0x33, 0x44, 0x55
};


## 7. Create uint8_t variable which will hold our dst_mac.

Broadcast MAC is used for ARP request.
uint8_t dst_mac[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

## 8. Create uint32_t variable which will hold our src_ip.

libnet_name2addr4 returns IP in network byte order.

uint32_t src_ip = libnet_name2addr4(
        l,
        "192.168.1.100",
        LIBNET_RESOLVE
    );


## 9. Create uint32_t variable which will hold our dst_ip (target IP).

uint32_t target_ip = libnet_name2addr4(
        l,
        "192.168.1.1",
        LIBNET_RESOLVE
    );


## 10. Target MAC which is unknown for ARP request.

Must be set to all zeros.

uint8_t target_mac[6] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


## 11. Build ARP header.

Call libnet_build_arp which returns libnet_ptag_t.

arp_tag = libnet_build_arp(
        ARPHRD_ETHER,        /* Ethernet hardware type */
        ETHERTYPE_IP,        /* IPv4 protocol type */
        6,                   /* MAC length */
        4,                   /* IPv4 length */
        ARPOP_REQUEST,       /* ARP request */
        src_mac,             /* Sender MAC */
        (uint8_t *)&src_ip,  /* Sender IP */
        target_mac,          /* Target MAC (unknown) */
        (uint8_t *)&target_ip, /* Target IP */
        NULL,                /* No payload */
        0,
        l,
        0
    );


## 12. Build Ethernet header.

Call libnet_build_ethernet which returns libnet_ptag_t.

eth_tag = libnet_build_ethernet(
        dst_mac,        /* Destination MAC */
        src_mac,        /* Source MAC */
        ETHERTYPE_ARP,  /* EtherType */
        NULL,
        0,
        l,
        0
    );


## 13. Send packet.

libnet_write(l) sends packet.

libnet_write(l);

