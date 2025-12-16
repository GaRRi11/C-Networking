#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define BUFFER_SIZE 1024
#define POOL_SIZE 50

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS 6
#define DHCP_OPTION_END 255

struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
};

// IP pool: simple array of available IPs
struct ip_entry {
    uint32_t ip;
    uint8_t allocated;
    uint8_t chaddr[16];
};

struct ip_entry pool[POOL_SIZE];

uint32_t base_ip;
uint32_t server_ip;
uint32_t gateway_ip;
uint32_t dns_ip;

int add_option(uint8_t *options, int *offset, uint8_t code, uint8_t length, uint8_t *data) {
    options[*offset] = code;
    options[*offset + 1] = length;
    memcpy(&options[*offset + 2], data, length);
    *offset += length + 2;
    return 0;
}

int find_free_ip(uint8_t *chaddr) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (!pool[i].allocated) {
            pool[i].allocated = 1;
            memcpy(pool[i].chaddr, chaddr, 16);
            return i;
        }
    }
    return -1;
}

int find_ip_by_chaddr(uint8_t *chaddr) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (pool[i].allocated && memcmp(pool[i].chaddr, chaddr, 16) == 0)
            return i;
    }
    return -1;
}

void fill_ip_pool() {
    for (int i = 0; i < POOL_SIZE; i++) {
        pool[i].ip = htonl(ntohl(base_ip) + i);
        pool[i].allocated = 0;
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    unsigned char buffer[BUFFER_SIZE];

    base_ip = inet_addr("192.168.1.100");   // start of pool
    server_ip = inet_addr("192.168.1.1");   // server IP
    gateway_ip = inet_addr("192.168.1.1");  // gateway
    dns_ip = inet_addr("8.8.8.8");          // DNS
    fill_ip_pool();

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int broadcast = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DHCP server running with pool of 50 IPs...\n");

    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            perror("recvfrom failed");
            continue;
        }

        struct dhcp_packet *recv_pkt = (struct dhcp_packet *)buffer;
        uint8_t dhcp_type = recv_pkt->options[2]; // simplified parsing

        if (dhcp_type == DHCP_DISCOVER) {
            int ip_idx = find_free_ip(recv_pkt->chaddr);
            if (ip_idx == -1) continue;

            struct dhcp_packet offer;
            memset(&offer, 0, sizeof(offer));
            offer.op = 2;
            offer.htype = 1;
            offer.hlen = 6;
            offer.xid = recv_pkt->xid;
            offer.yiaddr = pool[ip_idx].ip;
            offer.siaddr = server_ip;
            memcpy(offer.chaddr, recv_pkt->chaddr, 16);

            offer.options[0] = 99; offer.options[1] = 130;
            offer.options[2] = 83; offer.options[3] = 99;

            int opt_offset = 4;
            uint8_t msg_type = DHCP_OFFER;
            add_option(offer.options, &opt_offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);

            uint8_t subnet[] = {255, 255, 255, 0};
            add_option(offer.options, &opt_offset, DHCP_OPTION_SUBNET_MASK, 4, subnet);

            uint8_t router[4]; memcpy(router, &gateway_ip, 4);
            add_option(offer.options, &opt_offset, DHCP_OPTION_ROUTER, 4, router);

            uint8_t dns[4]; memcpy(dns, &dns_ip, 4);
            add_option(offer.options, &opt_offset, DHCP_OPTION_DNS, 4, dns);

            offer.options[opt_offset++] = DHCP_OPTION_END;

            struct sockaddr_in bcast_addr;
            memset(&bcast_addr, 0, sizeof(bcast_addr));
            bcast_addr.sin_family = AF_INET;
            bcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
            bcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

            sendto(sockfd, &offer, sizeof(offer), 0,
                   (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));

            printf("DHCPOFFER sent: %s\n", inet_ntoa(*(struct in_addr *)&pool[ip_idx].ip));
        }

        else if (dhcp_type == DHCP_REQUEST) {
            int ip_idx = find_ip_by_chaddr(recv_pkt->chaddr);
            if (ip_idx == -1) continue;

            struct dhcp_packet ack;
            memset(&ack, 0, sizeof(ack));
            ack.op = 2;
            ack.htype = 1;
            ack.hlen = 6;
            ack.xid = recv_pkt->xid;
            ack.yiaddr = pool[ip_idx].ip;
            ack.siaddr = server_ip;
            memcpy(ack.chaddr, recv_pkt->chaddr, 16);

            ack.options[0] = 99; ack.options[1] = 130;
            ack.options[2] = 83; ack.options[3] = 99;

            int opt_offset = 4;
            uint8_t msg_type = DHCP_ACK;
            add_option(ack.options, &opt_offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);

            uint8_t subnet[] = {255, 255, 255, 0};
            add_option(ack.options, &opt_offset, DHCP_OPTION_SUBNET_MASK, 4, subnet);

            uint8_t router[4]; memcpy(router, &gateway_ip, 4);
            add_option(ack.options, &opt_offset, DHCP_OPTION_ROUTER, 4, router);

            uint8_t dns[4]; memcpy(dns, &dns_ip, 4);
            add_option(ack.options, &opt_offset, DHCP_OPTION_DNS, 4, dns);

            ack.options[opt_offset++] = DHCP_OPTION_END;

            struct sockaddr_in bcast_addr;
            memset(&bcast_addr, 0, sizeof(bcast_addr));
            bcast_addr.sin_family = AF_INET;
            bcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
            bcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

            sendto(sockfd, &ack, sizeof(ack), 0,
                   (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));

            printf("DHCPACK sent: %s\n", inet_ntoa(*(struct in_addr *)&pool[ip_idx].ip));
        }
    }

    close(sockfd);
    return 0;
}
