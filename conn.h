#ifndef CONN_H
#define CONN_H
#include <map>
#include<stdlib.h>
#include<memory.h>
#include "pcap_process.h"
using namespace std;

struct epoint
{
    unsigned int v4{0};
    std::string strip;
    unsigned int port{0};

    epoint() {}
    epoint(unsigned int v4addr, std::string& sip,unsigned int p): v4(v4addr), strip(sip),port(p) {}
    epoint(epoint& e): v4(e.v4), strip(e.strip), port(e.port) {}

    bool operator==(epoint& t) {
        return t.v4 == v4 && t.port == port;
    }
    
};

#endif
