#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define CLIENT_COUNT 255

#define BATCH_SIZE 25
#define BATCH_DELAY_US 75000   // 75 ms
#define LISTEN_TIME 3          // seconds to collect offers

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_MAGIC 0x63825363
#define DHCP_DISCOVER 1
#define DHCP_REQUEST  3
#define DHCP_OFFER    2

#pragma pack(push, 1)
struct dhcp_packet {
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint8_t  options[312];
};
#pragma pack(pop)

struct dhcp_offer {
    uint32_t yiaddr;
    uint32_t server_id;
    uint8_t  mac[6];
    uint32_t xid;
    int received;
};

/* ------------------------------------------------------------ */

void random_mac(uint8_t mac[6]) {
    mac[0] = 0x02;
    for (int i = 1; i < 6; i++)
        mac[i] = rand() & 0xff;
}

int open_dhcp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int yes = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_CLIENT_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    return sock;
}

/* ------------------------------------------------------------ */

void send_discover(int sock, struct dhcp_offer *c) {
    struct dhcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.op = 1;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = c->xid;
    pkt.flags = htons(0x8000);
    memcpy(pkt.chaddr, c->mac, 6);

    uint8_t *o = pkt.options;
    *(uint32_t *)o = htonl(DHCP_MAGIC); o += 4;
    *o++ = 53; *o++ = 1; *o++ = DHCP_DISCOVER;
    *o++ = 255;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = INADDR_BROADCAST
    };

    sendto(sock, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&dst, sizeof(dst));
}

/* ------------------------------------------------------------ */

void send_request(int sock, struct dhcp_offer *c) {
    struct dhcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.op = 1;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = c->xid;
    pkt.flags = htons(0x8000);
    memcpy(pkt.chaddr, c->mac, 6);

    uint8_t *o = pkt.options;
    *(uint32_t *)o = htonl(DHCP_MAGIC); o += 4;
    *o++ = 53; *o++ = 1; *o++ = DHCP_REQUEST;
    *o++ = 50; *o++ = 4; memcpy(o, &c->yiaddr, 4); o += 4;
    *o++ = 54; *o++ = 4; memcpy(o, &c->server_id, 4); o += 4;
    *o++ = 255;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = INADDR_BROADCAST
    };

    sendto(sock, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&dst, sizeof(dst));
}

/* ------------------------------------------------------------ */

int main() {
    srand(time(NULL));
    int sock = open_dhcp_socket();

    struct dhcp_offer clients[CLIENT_COUNT];
    memset(clients, 0, sizeof(clients));

    /* Prepare clients */
    for (int i = 0; i < CLIENT_COUNT; i++) {
        clients[i].xid = rand();
        random_mac(clients[i].mac);
    }

    /* Send DISCOVERs in batches */
    for (int i = 0; i < CLIENT_COUNT; i++) {
        send_discover(sock, &clients[i]);
        printf("[DISCOVER] %d\n", i + 1);

        if ((i + 1) % BATCH_SIZE == 0) {
            usleep(BATCH_DELAY_US);
        }
    }

    /* Collect OFFERs */
    time_t start = time(NULL);
    while (time(NULL) - start < LISTEN_TIME) {
        struct dhcp_packet pkt;
        if (recv(sock, &pkt, sizeof(pkt), MSG_DONTWAIT) > 0) {
            for (int i = 0; i < CLIENT_COUNT; i++) {
                if (!clients[i].received &&
                    pkt.xid == clients[i].xid) {

                    clients[i].received = 1;
                    clients[i].yiaddr = pkt.yiaddr;

                    uint8_t *o = pkt.options + 4;
                    while (*o != 255) {
                        if (*o == 54)
                            memcpy(&clients[i].server_id, o + 2, 4);
                        o += o[1] + 2;
                    }

                    printf("[OFFER] xid=0x%x ip=%s\n",
                        pkt.xid,
                        inet_ntoa(*(struct in_addr *)&pkt.yiaddr));
                }
            }
        }
        usleep(1000);
    }

    /* Send REQUESTs */
    for (int i = 0; i < CLIENT_COUNT; i++) {
        if (clients[i].received) {
            send_request(sock, &clients[i]);
        }
    }

    close(sock);
    return 0;
}
