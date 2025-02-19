#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <cstdint>
#include <string>

namespace Options {

typedef struct {
    std::string filter_func;
    uint32_t filter_mark;
    std::string filter_pcap;
    std::string filter_ifname;
    std::string filter_netns;

    uint32_t filter_ifindex;
    uint32_t filter_netns_id;

    bool output_skb;
    bool output_stack;

    int verbose;
} args;

const args parse_args(int argc, char **argv);
int dump_args(const args &args);
bool resolve_netns_and_ifname(args &args, std::string &err_msg);

}

#endif //__OPTIONS_H__

