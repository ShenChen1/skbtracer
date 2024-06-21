#ifndef __BPF_COMMON_H__
#define __BPF_COMMON_H__

#include <string>
#include <vector>

namespace libbpf {
extern "C" {
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
}
} /* namespace libbpf */

namespace bpfhelper {
extern "C" {
#include "trace_helpers.h"
std::tuple<int, libbpf::bpf_insn *, size_t> compile_ebpf_filter(const std::string &filter_str, bool l3);
}
} /* namespace bpfhelper */

#endif //__BPF_COMMON_H__