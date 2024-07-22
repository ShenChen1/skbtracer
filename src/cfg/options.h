#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <string>

namespace Options {

typedef struct {
    std::string filter_func;
    std::string filter_mark;
    std::string filter_pcap;

    bool output_skb;
    bool output_stack;

    int verbose;
} args;

const args parse_args(int argc, char **argv);
int dump_args(const args &args);

}

#endif //__OPTIONS_H__

