#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <map>
#include<list>
#include<iostream>
#include <memory.h>
#include "conn.h"
using namespace std;

const char *timestamp_string(struct timeval ts);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
	timestamp_string(ts), truncated_hdr);
}

int  get_packet(const pcap_control_t* control,const unsigned char *pack, struct timeval ts,
			unsigned int caplen, packet_t *pkt)
{
	int olen = caplen;
	struct ip *ip = nullptr;
	struct UDP_hdr *udp = nullptr;
	struct TCP_hdr *tcp = nullptr;
	unsigned int ip_header_length;
    int dataoff = -1;
    int paylen = 0;
    int linklen = control->linkhdrsize;

	if (caplen < linklen) {
		too_short(ts, "Ethernet header");
		return -1;
	}

	pack += linklen;
	caplen -= linklen;

	if (caplen < sizeof(struct ip)) { /* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return -1;
	}

	ip = (struct ip*) pack;
	
	ip_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */
    unsigned int ver = ip->ip_v;
    pack += ip_header_length;

    if (ver != 4) {
        printf("Unsupported IPversion: [%d]\n",ver);
        return  -1;
    }
	if (caplen < ip_header_length) {
		too_short(ts, "IP header with options");
		return  -1;
	}
    int ip_total_len = ntohs(ip->ip_len);

	if (ip->ip_p == IPPROTO_UDP) {
		udp = (struct UDP_hdr*) pack;
	} else if (ip->ip_p == IPPROTO_TCP) {
		tcp = (struct TCP_hdr*) pack;
        const char *tcp1 = (const char *)pack;
        int tcp_header_length = ((*(tcp1 + 12)) & 0xF0) >> 4;
        tcp_header_length *=  4;
        if (ip_total_len == ip_header_length+ tcp_header_length) {
            paylen = 0;
            dataoff = 0;
        } else {
            dataoff = tcp_header_length+ ip_header_length + linklen;
            paylen = olen - dataoff;
        }
	} else {
		cout << "Unknown L4 protocol" << endl;
		return -1;
	}
    pkt->iph = ip;
    pkt->tcp = tcp;
    pkt->udp = udp;
    pkt->paylen = paylen;
    pkt->dataoff = dataoff;
    return pkt->dataoff;
}
