#ifndef __PCAP_2_BPF_H__
#define __PCAP_2_BPF_H__

#include <string>
#include <vector>

#include "bpf-common.h"

namespace pcap2bpf {
    std::tuple<int, libbpf::bpf_insn *, size_t> compile_ebpf_filter(const std::string &filter_str, bool l3);
    int inject_ebpf_filter(char *elf_data, size_t elf_size, libbpf::bpf_insn *prog, size_t len);
}

#endif //__PCAP_2_BPF_H__