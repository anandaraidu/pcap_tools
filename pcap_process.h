#ifndef P_H
#define P_H
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include<pcap.h>
#include<string>
typedef struct pcapcontrol
{
    pcap_t *pcap;
    int linkhdrsize;
} pcap_control_t;


struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};
typedef u_int tcp_seq;
struct TCP_hdr {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct packet_t
{
	struct UDP_hdr *udp{nullptr};
	struct TCP_hdr *tcp{nullptr};
	struct ip *iph{nullptr};
    int paylen{0};
    int dataoff{0};
	short   l4{IPPROTO_TCP};
    int getsaddr()  
    {
        return ntohl(iph->ip_src.s_addr);
    }
    int getdaddr()  
    {
        return ntohl(iph->ip_dst.s_addr);
    }
    std::string getsaddr_str()  
    {
        return inet_ntoa(iph->ip_src);
    }
    std::string getdaddr_str()  
    {
        return inet_ntoa(iph->ip_dst);
    }
    int getsport() 
    {
        return ntohs(tcp->th_sport);
     
    }
    int getdport() 
    {
        return ntohs(tcp->th_dport);
    }
    int getl4() {
        return l4;
    }
    void make_conn_key(std::string& k) 
    {
        const std::string sa  = this->getsaddr_str() + "_";
        const std::string da  = this->getdaddr_str() + "_";
        unsigned int sp = 0;
        unsigned int dp = 0;
        int proto = 0;
        if (this->l4 == IPPROTO_UDP ) {
            sp = this->getsport();
            dp = this->getdport();
            proto = 4;
        } else if (this->l4 == IPPROTO_TCP  ) {
            sp = this->getsport();
            dp = this->getdport();
            proto = 17;
        }

        int comp = sa.compare(da);
        bool sfirst = true;
        if (comp == 0) {
            if (sp < dp) {
                sfirst = true;
            } else {
                sfirst = false;
            }
        } else if (comp > 0) {
            sfirst = true;
        } else if (comp < 0) {
            sfirst = false;
        }

        if (sfirst) {
            k += sa + std::to_string(sp) + "_" + da + std::to_string(dp) + "_" +std::to_string(proto);
        } else {
            k += da + std::to_string(dp) + "_" + sa + std::to_string(sp) + "_" + std::to_string(proto);
        }
        //printf("Sport:[%d] Dport[%d] Key:%s\n",sp,dp,k.c_str());
    }

};
#endif
