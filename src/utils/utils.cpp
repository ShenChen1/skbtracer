#include "utils.h"

#include <spdlog/spdlog.h>

extern "C" {
#include <pcap/pcap.h>
#include <sys/resource.h>
}

void Utils::enforce_infinite_rlimit()
{
    struct rlimit rl = {};
    rl.rlim_max = RLIM_INFINITY;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);

    rl.rlim_max = 8192;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);
}

int Utils::compile_filter(const std::string &filter_str)
{
    struct bpf_program bf;
    pcap_t *pcap;

    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        spdlog::error("can not open pcap");
        return -EFAULT;
    }

    if (pcap_compile(pcap, &bf, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        spdlog::error("pcap filter string not valid (%s)", pcap_geterr(pcap));
        return -EFAULT;
    }

    /* Don't care about original program any more */
    pcap_freecode(&bf);
    pcap_close(pcap);

    return 0;
}