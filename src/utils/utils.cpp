#include "utils.h"

#include <pcap/pcap.h>
#include <sys/resource.h>
#include <string>

void enforce_infinite_rlimit()
{
    struct rlimit rl = {};

    rl.rlim_max = RLIM_INFINITY;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);
    setrlimit(RLIMIT_NOFILE, &rl);
}

int pcap_prepare_compile()
{
    std::string filter_exp = "port 23";
    struct bpf_program fp;
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    // 编译过滤表达式
    return pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN);
}