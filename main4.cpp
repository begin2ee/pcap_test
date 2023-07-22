#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

#define ETH_ALEN 6
#define IPV4_ALEN 4
#define IPV4_HL_MIN 5
#define TCP_PAYLOAD_MAXLEN 16
#define TCP_HL_MIN 20

void usage() {
    puts("syntax: ./main <interface>");
    puts("sample: ./main eth0");
}

void print_payload(const uint8_t* packet_data, uint32_t offset, uint32_t payload_length) {
    for (uint32_t i = offset; i < offset + payload_length; ++i) {
        printf("%s%02X", ((i - offset) ? " " : ""), packet_data[i]);
    }
    puts("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Can't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet_data;
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        const struct eth_hdr* ethernet_header = (const struct eth_hdr*)packet_data;
        printf("[MAC] ");
        printf("src: %02X:%02X:%02X:%02X:%02X:%02X", ethernet_header->src[0], ethernet_header->src[1],
               ethernet_header->src[2], ethernet_header->src[3], ethernet_header->src[4], ethernet_header->src[5]);
        printf(" -> dst: %02X:%02X:%02X:%02X:%02X:%02X", ethernet_header->dst[0], ethernet_header->dst[1],
               ethernet_header->dst[2], ethernet_header->dst[3], ethernet_header->dst[4], ethernet_header->dst[5]);
        puts("");

        uint16_t eth_type = ntohs(ethernet_header->type);
        if (eth_type != 0x0800) {
            puts("Ethertype : not ipv4\n");
            continue;
        }

        const struct ipv4_hdr* ipv4_header = (const struct ipv4_hdr*)(packet_data + sizeof(struct eth_hdr));
        printf("[IP] ");
        printf("src: %d.%d.%d.%d", ipv4_header->src[0], ipv4_header->src[1], ipv4_header->src[2], ipv4_header->src[3]);
        printf(" -> dst: %d.%d.%d.%d", ipv4_header->dst[0], ipv4_header->dst[1], ipv4_header->dst[2], ipv4_header->dst[3]);
        puts("");

        uint8_t ihl = (ipv4_header->version_ihl & 0x0F);
        if (ihl < IPV4_HL_MIN) {
            puts("Invalid ipv4 packet\n");
            return 2;
        }

        printf("[TYPE] ");
        if (ipv4_header->protocol != 0x06) {
            puts("NOT TCP PROTOCOL\n");
            continue;
        }

        puts("TCP PROTOCOL");
        const struct tcp_hdr* tcp_header = (const struct tcp_hdr*)((uint8_t*)ipv4_header + (ihl * 4));

        uint16_t length = ntohs(ipv4_header->length) - (ihl * 4);
        printf("[PORT] %d -> %d\n", ntohs(tcp_header->src), ntohs(tcp_header->dst));

        uint8_t thl = ((tcp_header->offset_flags >> 4) & 0x0F) * 4;
        if (thl < TCP_HL_MIN || thl > 60) {
            puts("Invalid tcp packet\n");
            return 2;
        }

        uint32_t tl = length - thl;
        printf("[Payload] ");
        tl = tl < TCP_PAYLOAD_MAXLEN ? tl : TCP_PAYLOAD_MAXLEN;
        print_payload(packet_data, sizeof(struct eth_hdr) + (ihl * 4) + (thl - TCP_HL_MIN), tl);
    }

    pcap_close(handle);
    return 0;
}

