#ifndef __PCAP_2_BPF_H__
#define __PCAP_2_BPF_H__

#include <string>
#include <vector>

#include "bpf-common.h"

namespace pcap2bpf {
    std::tuple<int, libbpf::bpf_insn *, size_t> compile_ebpf_filter(const std::string &filter_str, bool l3);
    int inject_ebpf_filter(const std::string &obj_path, const std::string &function, const libbpf::bpf_insn *prog_data, size_t prog_len);
}

#endif //__PCAP_2_BPF_H__