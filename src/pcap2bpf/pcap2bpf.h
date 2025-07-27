#ifndef __PCAP_2_BPF_H__
#define __PCAP_2_BPF_H__

#include <string>
#include <utility>
#include <vector>

#include "bpf-common.h"

namespace pcap2bpf {
    std::pair<int, std::vector<libbpf::bpf_insn>> compile_ebpf_filter(const std::string &filter_str, bool l3);
    std::vector<libbpf::bpf_insn> make_constant_filter(bool condition);
    int inject_ebpf_filter(libbpf::bpf_program *prog, size_t position, size_t orig_len,
                           const std::vector<libbpf::bpf_insn> &insns);
}

#endif //__PCAP_2_BPF_H__
