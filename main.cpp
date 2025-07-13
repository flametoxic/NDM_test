#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define BUFFER_SIZE 1024

class MACAddressPrinter {
public:
    void print(const unsigned char *mac) const {
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
};

class ICMPClient {
private:
    int sockfd;
    struct sockaddr_in targetAddr;

public:
    ICMPClient() {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd == -1) {
            throw std::runtime_error("Failed to create ICMP socket");
        }
    }

    ~ICMPClient() {
        close(sockfd);
    }

    bool sendEchoRequest(const std::string& ip) {
        std::memset(&targetAddr, 0, sizeof(targetAddr));
        targetAddr.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &(targetAddr.sin_addr)) <= 0) {
            std::cerr << "Invalid IPv4 address: " << ip << std::endl;
            return false;
        }

        struct icmphdr icmpHdr{};
        icmpHdr.type = ICMP_ECHO;
        icmpHdr.code = 0;
        icmpHdr.un.echo.id = getpid();
        icmpHdr.un.echo.sequence = 1;
        icmpHdr.checksum = 0;
        icmpHdr.checksum = calculateChecksum((unsigned short*)&icmpHdr, sizeof(icmpHdr));

        if (sendto(sockfd, &icmpHdr, sizeof(icmpHdr), 0,
                   (struct sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
            std::cerr << "Failed to send ICMP echo request" << std::endl;
            return false;
        }

        return true;
    }

private:
    unsigned short calculateChecksum(unsigned short* buffer, int size) {
        unsigned long sum = 0;
        while (size > 1) {
            sum += *buffer++;
            size -= 2;
        }
        if (size == 1)
            sum += *(unsigned char*)buffer;

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);

        return static_cast<unsigned short>(~sum);
    }
};

class PacketSniffer {
private:
    int sockfd;

public:
    PacketSniffer() {
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd == -1) {
            throw std::runtime_error("Failed to create packet socket");
        }
    }

    ~PacketSniffer() {
        close(sockfd);
    }

    bool receiveEchoReply(const std::string& ip, MACAddressPrinter& printer) {
        unsigned char buffer[BUFFER_SIZE];
        ssize_t bytesReceived = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, nullptr, nullptr);
        if (bytesReceived < 0) {
            std::cerr << "Failed to receive packet" << std::endl;
            return false;
        }

        struct ether_header *ethHdr = reinterpret_cast<struct ether_header*>(buffer);
        if (ntohs(ethHdr->ether_type) != ETHERTYPE_IP) {
            std::cerr << "Not an IP packet" << std::endl;
            return false;
        }

        struct iphdr *ipHdr = reinterpret_cast<struct iphdr*>(buffer + sizeof(struct ether_header));
        if (ipHdr->protocol != IPPROTO_ICMP) {
            std::cerr << "Not an ICMP packet" << std::endl;
            return false;
        }

        struct icmphdr *icmpHdr = reinterpret_cast<struct icmphdr*>((char*)ipHdr + (ipHdr->ihl << 2));
        if (icmpHdr->type != ICMP_ECHOREPLY) {
            std::cerr << "Not an ICMP echo reply" << std::endl;
            return false;
        }

        if (icmpHdr->un.echo.id != getpid()) {
            std::cerr << "Received ICMP reply from another process" << std::endl;
            return false;
        }

        std::cout << "MAC address of sender: ";
        printer.print(ethHdr->ether_shost);

        return true;
    }
};

class ICMPPingApp {
private:
    std::string targetIP;
    ICMPClient icmpClient;
    PacketSniffer packetSniffer;
    MACAddressPrinter macPrinter;

public:
    ICMPPingApp(const std::string& ip)
        : targetIP(ip) {}

    int run() {
        std::cout << "Sending ICMP echo request to " << targetIP << std::endl;

        if (!icmpClient.sendEchoRequest(targetIP)) {
            std::cerr << "Error sending ICMP request" << std::endl;
            return 1;
        }

        std::cout << "Waiting for response..." << std::endl;

        if (!packetSniffer.receiveEchoReply(targetIP, macPrinter)) {
            std::cerr << "Error receiving ICMP reply" << std::endl;
            return 1;
        }

        return 0;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IPv4 address>" << std::endl;
        return 1;
    }

    try {
        ICMPPingApp app(argv[1]);
        return app.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}