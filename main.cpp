#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
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
#include<math.h>
int running = 1;
using namespace std;
std::string dumpdir = "/home/ananda/smartapps/payload_analysis/";
class KNOWN_PROTOCOLS
{
public:
    static const int TLS12 = 23;
};

enum SUPPORTED_FEATURES
{
    SPLIT_STREAMS_AND_WRITE = 1,
    SERVER_NAME_INDICATOIN,
    AGGREGATE_ALL_IPS,
    CAPTURE_CERTIFICATES,
    APPLICATION_ANALYSIS
};

int application = CAPTURE_CERTIFICATES;
KNOWN_PROTOCOLS protocols;
class connection_details;
struct buff_t;
int parse_from_buf( std::shared_ptr<connection_details> cd, buff_t *);
void print_n_bytes(const unsigned char*p,int n)
{
    for (auto i=0;i<n;i++) {
        printf("%x ",p[i]);
    }
} 
int  get_packet(const pcap_control_t* control,const unsigned char *pack, struct timeval ts,
			unsigned int caplen, packet_t *pkt);

struct buff_t {
    buff_t() {
        p  = nullptr;
        sz = 0;
        //off = 0;
    }
    ~buff_t() {
        if (p) delete p;
        p = nullptr;
        sz = 0;
    }
    unsigned char *p;
    int sz;
    //int off;
    
    void deletebuff() {
        delete p;
        p = nullptr;
        sz = 0;
    }

    void appendto(unsigned const char *ptr,int ln) {
        int currlen = sz;
        unsigned char *np = new unsigned char[ln+sz];
        if (p) {
            memcpy(np,p,sz);
            delete p;
            p = nullptr;
        }
        memcpy(np+sz,ptr,ln);
        sz += ln;
        p = np;
        //printf("Append Rcvd: %d SizeBefore:[%d[ After[%d] \n",ln,currlen,sz);
        //print_n_bytes(p,10);
        //printf("end of print...\n");
    }
   
    //done:= is the number of bytes completed processing in the buf and 
    //done is not the offset. 
    void remaining_to_newbuf(int done)
    {
        int remaining = sz - done;
        unsigned char *np = new unsigned char[remaining];
        sz = remaining;
        memcpy(np,p+done,remaining);
        delete p;
        p = np;
        sz = remaining;
        //printf("Remaining copied: %d\n",remaining);
    }
};

struct cl2s
{
public:
    cl2s() {
    }
    ~cl2s() {
    }
    buff_t buf;
};

struct s2cl
{
    s2cl() {
    }
    ~s2cl() {
    }
    buff_t buf;
};

class connection_details: public std::enable_shared_from_this<connection_details>
{
public:
    pcap_dumper_t *dumper{nullptr};
    cl2s c2s;
    s2cl s2c;
    //buff_t buf;
    int l7 = 0;
    epoint src;
    connection_details(pcap_t *pcap, std::string& key,epoint& e):src(e)
    {
        if (application == SPLIT_STREAMS_AND_WRITE) {
            std::string fn = dumpdir + key + ".pcap";
            dumper = pcap_dump_open(pcap, fn.c_str());
        }
    }

    buff_t* get_buff(bool cl2s) {
        if (cl2s) return &(s2c.buf);
        return &c2s.buf;
    }

    bool is_c2s( packet_t *pkt)
    {
        return (src.v4 == pkt->getsaddr()) && (src.port == pkt->getsport());
    }
    ~connection_details() {
        if (dumper) {
            pcap_dump_flush(dumper);
            pcap_dump_close(dumper);
        }
    }

    void write_packet( const unsigned char *packet, struct pcap_pkthdr* header) {
        pcap_dump((u_char *)dumper, header, packet);
    }
    void flush_pending() {
        while (c2s.buf.p) {
            if (0 == parse_from_buf(shared_from_this(), &c2s.buf)) {
                break;
            }
        }
        while (s2c.buf.p) {
            if (0 == parse_from_buf(shared_from_this(), &s2c.buf)) {
                break;
            }
        }
    }
};

class connectionsv4
{
private:
    std::map<std::string, bool> allips;

public:
    std::map<std::string, std::shared_ptr<connection_details> > conns;

    void add_ip(packet_t *pkt) 
    {
        std::string s = pkt->getdaddr_str();
        auto it = allips.find(pkt->getdaddr_str());
        if (it == allips.end()) {
            allips.insert(std::make_pair(s,true));
        }
    }

    connectionsv4() {
    }

    void print_allips() {
        for (auto &[ip, b] : allips) {
            std::cout <<  ip << "\n";
        }
    }

    ~connectionsv4() {
        //printf("Number of connections is: %lu\n",conns.size());
        for (auto& [k,cd] : conns) 
        {
            cd = nullptr;
        }
        conns.clear();
        print_allips();
    }
    std::shared_ptr<connection_details> getconn(pcap_t* pcap, packet_t* pkt)
    {
        std::string connkey;
        pkt->make_conn_key(connkey);
        auto it = conns.find(connkey);
        if (it == conns.end() ) {
            std::string sip = pkt->getsaddr_str();
            epoint e(pkt->getsaddr(), sip, pkt->getsport()); 
            std::shared_ptr<connection_details> cd(new connection_details(pcap, connkey, e));
            conns.insert(make_pair(connkey, cd));
            return cd;
        }
        return it->second;
    }

    void packet_write_func(pcap_t *pcap, packet_t *pkt, const unsigned char *packet, struct pcap_pkthdr* header)
    {
        auto cd =  getconn(pcap,  pkt);
        cd->write_packet( packet, header);
    }
#if 0
    void flush_all_pending_conns() {
        for (auto& [k,cd] : conns) 
        {
            while (cd->c2s.buf.p) {
                if (0 == parse_from_buf(cd, &cd->c2s.buf)) {
                    break;
                }
            }
            while (cd->s2c.buf.p) {
                if (0 == parse_from_buf(cd, &cd->s2c.buf)) {
                    break;
                }
            }
        }
    }
#endif
    void flush_all_pending_conns() {
        for (auto& [k,cd] : conns) 
        {
            cd->flush_pending();
        }
    }
};


int byte_to_int(unsigned char a) {
    //unsigned char a = 0x38;
    int v1 = a & 0x0F;
    int v2 = (a  >> 4)& 0x0F;
    int v = v1 + 16*v2;
    return v;
}

int bytes_to_int(const unsigned char* p, int n)
{
    int v = 0;
    int x = n-1;
    for (auto i=0;i<n;i++) {
        v += (byte_to_int(p[x]) * pow(256,i));
        --x;
    }
    return v;
}

void print_servername_indication(packet_t *pkt,const unsigned char *p)
{
    p += 2;//list len
    p += 1; //host type
    int ln = bytes_to_int(p,2);
    p+=2; //len of len bytes
    printf("SNI:[%.*s] %s\n",ln,p, pkt->getdaddr_str().c_str());
    //print_n_bytes(p,ln);
    //printf("]\n");
}

//tlv t=2 len=2 val= data of len bytes
std::tuple<int,int,int> parse_extension(packet_t *conn, const unsigned char* p) 
{
    int type = bytes_to_int(p, 2);
    p += 2;
    int len  = bytes_to_int(p, 2);
    p += 2;
    if (type == 0) {
        print_servername_indication(conn,p);
    }
    return std::make_tuple(type,len,4);
}

//int process_server_cert( connv4* conn,const unsigned char *appdata, int applen, int reclen)
int process_server_cert( const unsigned char *appdata, int applen, int reclen)
{
    int fh = 5;
    int sh = 7; //type = 11 len=3 certlen=3
    int remaining = reclen - 7;
    const unsigned char *p =  appdata;
    p += fh;
    p += sh;
    //printf("Remaining:[%d]\n",remaining);
    while (remaining > 0) {
        int clen = bytes_to_int( p, 3);
        p += 3;
        printf("CertLen: %d\n", clen);
        //void print_cert(p,clen);
        //printf("%.*s\n",clen,p);
        p += clen;
        remaining -= 3;
        remaining -= clen;
        //printf("Remaining:[%d]\n",remaining);
    }
    int parsed = p-appdata;
    //printf("Certs parsed: %d\n",parsed);
    return parsed;
}
/*
    5 bytes first header 
    6 bytes record header
*/
void process_client_hello( packet_t* conn,const unsigned char *appdata, int applen)
{
    int fh = 5;
    int sh = 6;
    int rn = 32; 
    //char *parse_limit = appdata + applen;
    const unsigned char *p =  appdata;
    //print_n_bytes(p,10);
    p += (fh+sh+rn);
    int sl = bytes_to_int(p,1);
    //printf("%x SessionIdLen: %d\n",*p,sl);
    p+= 1; //skip session len byte
    p += sl;
    int cl = bytes_to_int(p,2);
    //printf("CipherSuiteLen: %x %d\n",*(p+1),cl);
    p += 2;
    p += cl;
    int cmplen = bytes_to_int(p,1);
    p++; //compression methods len
    p += cmplen;
    int extlen = bytes_to_int(p,2);
    p+=2;
    //printf("Extension Len: %x %x %d\n",*p,*(p+1),extlen);
    //for (int pos =0;pos < extlen; pos++) {
    for (int pos =0;pos < extlen;)  {
        auto [etype, elen, eoff]  = parse_extension(conn,p);
        //printf("Etype %d elen %d\n",etype,elen);
        p += (elen + eoff);
        pos += (elen + eoff);
    }
}

int parse_tls12( const unsigned char *appdata, int applen)
{
    if (applen < 5) return 0; //need more data this is not enough

    int reclen = bytes_to_int(appdata+3,2);
    if (reclen > applen) return 0;
    print_n_bytes(appdata,10);

    unsigned int ctype = appdata[0];
    unsigned int htype = appdata[5];

    int parsed = 0;
    parsed = reclen + 5;
    if (ctype == 22) {
        if (htype==1) {
            //process_client_hello(  conn, appdata, applen);
            parsed = reclen + 5;
        } else if (htype == 11) {
            //parsed = process_server_cert(  conn, appdata, applen, reclen);
            parsed = process_server_cert(   appdata, applen, reclen);
        } else {
            //printf("Unknown... header type\n");
            parsed = reclen + 5;
        }
    }
    
    printf("\nSSL handshake Recordtype[%x] ContenType:[%x] reclen:%d parsed: %d\n",ctype,htype,reclen,parsed);
    return parsed;
}

int get_proto(const unsigned char *p, int ln)
{
    if (p[1] == 0x03 && p[2] == 0x03 && p[9] == 0x03 && p[10] == 0x03)
        return protocols.TLS12;
    return 0;
}

int process_app_data( std::shared_ptr<connection_details> cd, const unsigned char *appdata, int applen)
{
    int proto = cd->l7;
    if (proto  == 0) {
        proto = get_proto(appdata, applen);
    }
    int parsed = applen;
    
    switch (proto) {
        case protocols.TLS12:
            cd->l7 = proto;
            //parsed = parse_tls12(conn, appdata, applen);
            parsed = parse_tls12( appdata, applen);
            //printf("Parsed in tls12::= %d\n",parsed);
            break;
        default:
            //printf("Protocol unknown...\n");
            break;
    }
    return parsed;
}


int parse_from_buf(std::shared_ptr<connection_details> cd, buff_t *buf)
{
    //printf("Parsing from Buf\n");
    int done = process_app_data(cd,buf->p, buf->sz);
/*
        1. complete : 0 outstanding ==> nothing to store
        2. complete :  x remaining ==> store x bytes starting from p+done
        3. not complete: store all
*/
    if (done >= buf->sz) {
        buf->deletebuff();
    } else if (done > 0) {
        buf->remaining_to_newbuf(done);
    }
    return done;
}

int cert_analysis(pcap_t *pcap,connectionsv4 *conns, packet_t *pkt,unsigned const char*p, int ln)
{
    if (pkt->paylen <= 0) return 0;
    std::shared_ptr<connection_details> cd = conns->getconn(pcap, pkt);
    bool c2s = cd->is_c2s(pkt);
    buff_t *buf = cd->get_buff(c2s);
    if (buf->p) {
        buf->appendto(p,ln);
        parse_from_buf(cd, buf);
    } else {
        int done = process_app_data( cd,  p , ln);
/*
        1. complete : 0 outstanding ==> nothing to store
        2. complete :  x remaining ==> store x bytes starting from p+done
        3. not complete: store all
*/
        if (ln > done) { //this if will handle all the above 3 conditions
            //printf("There is something remaining\n");
            buf->appendto(p+done,ln-done);
        }
    }
}

int packet_recvd(pcap_t *pcap, connectionsv4 *conns, pcap_pkthdr* hdr, unsigned const char *rawpkt, packet_t *pkt,unsigned const char*p, int ln)
{

    switch (application) {
        case SPLIT_STREAMS_AND_WRITE:
            conns->packet_write_func( pcap, pkt, rawpkt, hdr);
            break;
        case SERVER_NAME_INDICATOIN:
            break;
        case AGGREGATE_ALL_IPS:
            break;
        case CAPTURE_CERTIFICATES:
            cert_analysis(pcap, conns, pkt, p, ln);
            break;
        case APPLICATION_ANALYSIS:
            break;
        default:
            break;
    }
    return 0;
}
void usage() {
		fprintf(stderr, "program requires 1 arguments, ./a.out feature <PcapFile>\n");
        printf("Supported features are:\n");
        printf("      :SPLIT_STREAMS_AND_WRITE  ==> 1\n");
        printf("      :SERVER_NAME_INDICATOIN   ==> 2\n");
        printf("      :AGGREGATE_ALL_IPS        ==> 3\n");
        printf("      :CAPTURE_CERTIFICATES     ==> 4\n");
        printf("      :APPLICATION_ANALYSIS     ==> 5\n");
		exit(1);
}
int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct pcap_pkthdr wheader;
    pcap_file_header *p1 = nullptr; //unused
    pcap_control_t control;

	if ( argc != 3 )
	{
        usage();
	}
    application = atoi(argv[1]);
    if (application <= 0) {
        usage();
    }
    if (application > 5) {
        usage();
    }
    
	pcap = pcap_open_offline(argv[2], errbuf);
	if (nullptr == pcap)
	{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
    int datalink = pcap_datalink(pcap);
    printf("DataLink: %d\n",datalink);
    control.pcap = pcap;
    if (datalink == 0) {
        control.linkhdrsize = 4;
    } else if (datalink == 1) {
        control.linkhdrsize = 14;
    } else {
        printf("Unknown LinkType: .... datalink: %d\n",datalink);
        exit(1);
    }


	/* Now just loop through extracting packets as long as we have
	 */
    connectionsv4 conns;
	while ((packet = pcap_next(pcap, &header)) != NULL) {
        packet_t pkt;
		int appoff = get_packet(&control,packet, header.ts, header.caplen,&pkt);
		if (appoff >= 0) {
            const unsigned char *appdata =  packet + pkt.dataoff;
            packet_recvd(pcap, &conns, &header, packet,&pkt, appdata, pkt.paylen);
            conns.add_ip(&pkt);
        } 
	}
    conns.flush_all_pending_conns();
	return 0;
}
