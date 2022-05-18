#pragma once

#include "srsran/srslog/srslog.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

namespace srsran {

namespace mitm_utils
{
typedef struct packet packet_t;

struct iphdr
{
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// DNS header's structure
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT; // Number of questions
    unsigned short int ANCOUNT; // Number of answers
    unsigned short int NSCOUNT; // Number of name server records
    unsigned short int ARCOUNT; // Number of additional records
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears.
struct dataEnd
{
    unsigned short int type;
    unsigned short int dataClass;
};

struct packet
{
    iphdr *ip;
    udpheader *udp;
    dnsheader *dns;
    const uint8_t *dnsdata;
};

packet parse_packet(uint8_t *data)
{
    struct iphdr *ip = (struct iphdr *)data;
    struct udpheader *udp = (struct udpheader *)(data + sizeof(struct iphdr));
    struct dnsheader *dns = (struct dnsheader *)(data + sizeof(struct iphdr) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    const uint8_t *dnsdata = (data + sizeof(struct iphdr) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    packet_t pckt = {ip, udp, dns, dnsdata};
    return pckt;
}

void set_dest_ip(packet_t *p, const std::string &ip)
{
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    p->ip->iph_destip = addr.s_addr;
}

void set_dest_port(packet_t *p, unsigned short port)
{
    p->udp->udph_destport = htons(port);
}

void set_source_ip(packet_t *p, const std::string &ip)
{
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    p->ip->iph_sourceip = addr.s_addr;
}

void set_source_port(packet_t *p, unsigned short port)
{
    p->udp->udph_srcport = htons(port);
}

const uint8_t *packet_to_buffer(packet_t *p)
{
    return (const uint8_t *)p;
}

// UDP checksum
uint16_t udp_checksum(const void *buffer, size_t length, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf = (uint16_t *)buffer; /* treat input as bunch of uint16_t's */
    uint16_t *src_ip = (uint16_t *) &src_addr; 
    uint16_t *dest_ip = (uint16_t *)&dest_addr;
    uint32_t sum;
    size_t len = length;

    sum = 0; 

    /* fold the carry bits for the buffer */
    while (length > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16); /* fold  carries */
        length -= 2;
    }

    if(length & 1)
        sum += *((uint8_t *)buf); // add the padding if packet length is odd */

    /* inject checksum of the pseudo-header */
    sum += *(src_ip++);
    sum += *(src_ip);

    sum += *(dest_ip++);
    sum += *(dest_ip);

    sum += htons(IPPROTO_UDP); /* protocol info */
    sum += htons(len); /* original length! */

    /* fold any carry bits created by adding header sums */
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

void compute_udp_checksum(packet_t *p, int packetLength)
{
    p->udp->udph_chksum = 0;
    p->udp->udph_chksum = udp_checksum(p->udp, packetLength - sizeof(struct iphdr), p->ip->iph_sourceip, p->ip->iph_destip);
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_ip_checksum_util(unsigned short *addr, unsigned int count)
{
    register unsigned long sum = 0;
    while (count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (count > 0)
    {
        sum += ((*addr) & htons(0xFF00));
    }
    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

void compute_ip_checksum(packet_t *p)
{
    p->ip->iph_chksum = 0;
    p->ip->iph_chksum = compute_ip_checksum_util((unsigned short *)p->ip, p->ip->iph_ihl << 2);
}

void apply_checksums(packet_t *p, int packetLength)
{
    compute_ip_checksum(p);
    compute_udp_checksum(p, packetLength);
}

void print_packet(uint8_t *pdu, int packetLength){
    std::cout << "START PACKET" << std::endl;
    fflush( stdout );
    for (int i = 0; i < packetLength; i++) {
        uint8_t h = pdu[i] & 0xff;
        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << h << std::endl;
    } 
    std::cout << "END PACKET" << std::endl;
}

} // namespace utils

} // namespace srsran