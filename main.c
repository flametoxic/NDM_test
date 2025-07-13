#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define BUFFER_SIZE 1024

void print_mac_address(const unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

unsigned short calculate_icmp_checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1)
        sum += *(unsigned char *)buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IPv4 address>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    struct sockaddr_in target_addr;
    struct icmphdr icmp_hdr;
    struct iphdr ip_hdr;
    unsigned char buffer[BUFFER_SIZE];

    int icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_socket == -1) {
        perror("Failed to create ICMP socket");
        return 1;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &(target_addr.sin_addr)) <= 0) {
        perror("Invalid IPv4 address");
        close(icmp_socket);
        return 1;
    }

    icmp_hdr.type = ICMP_ECHO;             
    icmp_hdr.code = 0;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = 1;
    icmp_hdr.checksum = 0;
    icmp_hdr.checksum = calculate_icmp_checksum((unsigned short *)&icmp_hdr, sizeof(icmp_hdr));

    if (sendto(icmp_socket, &icmp_hdr, sizeof(icmp_hdr), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("Failed to send ICMP echo request");
        close(icmp_socket);
        return 1;
    }

    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (packet_socket == -1) {
        perror("Failed to create packet socket");
        close(icmp_socket);
        return 1;
    }

    socklen_t addr_len = sizeof(struct sockaddr_ll);
    ssize_t bytes_received = recvfrom(packet_socket, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (bytes_received < 0) {
        perror("Failed to receive packet");
        close(icmp_socket);
        close(packet_socket);
        return 1;
    }

    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "Not an IP packet\n");
        close(icmp_socket);
        close(packet_socket);
        return 1;
    }

    struct iphdr *ip_hdr_recv = (struct iphdr *)(buffer + sizeof(struct ether_header));
    if (ip_hdr_recv->protocol != IPPROTO_ICMP) {
        fprintf(stderr, "Not an ICMP packet\n");
        close(icmp_socket);
        close(packet_socket);
        return 1;
    }

    struct icmphdr *icmp_hdr_recv = (struct icmphdr *)((char *)ip_hdr_recv + (ip_hdr_recv->ihl << 2));
    if (icmp_hdr_recv->type != ICMP_ECHOREPLY) {
        fprintf(stderr, "Not an ICMP echo reply\n");
        close(icmp_socket);
        close(packet_socket);
        return 1;
    }

    if (icmp_hdr_recv->un.echo.id != getpid()) {
        fprintf(stderr, "Received ICMP reply from another process\n");
        close(icmp_socket);
        close(packet_socket);
        return 1;
    }

    printf("MAC address of sender: ");
    print_mac_address(eth_hdr->ether_shost);

    close(icmp_socket);
    close(packet_socket);
    return 0;
}
