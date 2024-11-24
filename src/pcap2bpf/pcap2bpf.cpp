#include <string>
#include <vector>
#include <cstring>
#include <spdlog/spdlog.h>

#include "pcap2bpf.h"

namespace cbpf {
extern "C" {
#include <pcap/pcap.h>
}
} /* namespace cbpf */

extern "C" {
int bpf_convert_filter(libbpf::sock_filter *prog, int len,
                       libbpf::bpf_insn *new_prog, int *new_len);
int get_insns_for_filter_empty(libbpf::bpf_insn **data, int *len);
}

static std::pair<int, libbpf::sock_fprog> compile_cbpf_filter(const std::string &filter_str, bool l3)
{
    constexpr int MAXIMUM_SNAPLEN = 262144;
    int err = 0;
    libbpf::sock_fprog sf = { 0, nullptr };
    cbpf::bpf_program bf = { 0, nullptr };
    int linktype = l3 ? DLT_RAW : DLT_EN10MB;

    cbpf::pcap_t *pcap = cbpf::pcap_open_dead(linktype, MAXIMUM_SNAPLEN);
    if (!pcap) {
        spdlog::error("Cannot open dead pcap context");
        return { -EFAULT, sf };
    }

    if (cbpf::pcap_compile(pcap, &bf, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        spdlog::error("Invalid pcap filter expression '{}': {}", filter_str, cbpf::pcap_geterr(pcap));
        err = -EINVAL;
        goto end;
    }

    sf.len = bf.bf_len;
    sf.filter = new libbpf::sock_filter[sf.len];
    if (!sf.filter) {
        spdlog::error("Failed to allocate memory for sock_filter");
        err = -ENOMEM;
        goto end;
    }
    for (size_t i = 0; i < sf.len; i++) {
        sf.filter[i].code = bf.bf_insns[i].code;
        sf.filter[i].jt = bf.bf_insns[i].jt;
        sf.filter[i].jf = bf.bf_insns[i].jf;
        sf.filter[i].k = bf.bf_insns[i].k;
    }

end:
    cbpf::pcap_freecode(&bf);
    cbpf::pcap_close(pcap);
    return { err, sf };
}

std::tuple<int, libbpf::bpf_insn *, size_t> pcap2bpf::compile_ebpf_filter(const std::string &filter_str, bool l3)
{
    if (filter_str.empty()) {
        libbpf::bpf_insn *ebpf = nullptr;
        int len = 0;
        int err = get_insns_for_filter_empty(&ebpf, &len);
        return { err, ebpf, (size_t)len };
    }

    auto [ret, cbpf] = compile_cbpf_filter(filter_str, l3);
    if (ret) {
        return { ret, nullptr, 0 };
    }

    int ebpf_len = 0;
    ret = bpf_convert_filter(cbpf.filter, cbpf.len, nullptr, &ebpf_len);
    if (ret) {
        spdlog::error("Failed to calculate eBPF filter length");
        delete[] cbpf.filter;
        return { ret, nullptr, 0 };
    }

    auto ebpf = new libbpf::bpf_insn[ebpf_len];
    ret = bpf_convert_filter(cbpf.filter, cbpf.len, ebpf, &ebpf_len);
    delete[] cbpf.filter;
    if (ret) {
        spdlog::error("Failed to convert cBPF filter to eBPF");
        delete[] ebpf;
        return { ret, nullptr, 0 };
    }

    spdlog::debug("Compiled cBPF ({}) to eBPF ({} instructions)", cbpf.len, ebpf_len);
    return { 0, ebpf, (size_t)ebpf_len };
}

static bool insn_is_subprog_call(const libbpf::bpf_insn *insn)
{
    return BPF_CLASS(insn->code) == BPF_JMP &&
           BPF_OP(insn->code) == BPF_CALL &&
           BPF_SRC(insn->code) == BPF_K &&
           insn->src_reg == BPF_PSEUDO_CALL &&
           insn->dst_reg == 0 &&
           insn->off == 0;
}

int pcap2bpf::inject_ebpf_filter(libbpf::bpf_program *prog, size_t position, size_t orig_len, const libbpf::bpf_insn *data, size_t len)
{
    auto old_len = libbpf::bpf_program__insn_cnt(prog);
    auto old_data = libbpf::bpf_program__insns(prog);

    if (position + orig_len > old_len) {
        spdlog::error("Invalid inject position {} + orig_len {} > old_len {}", position, orig_len, old_len);
        return -EINVAL;
    }

    auto new_len = old_len - orig_len + len;
    libbpf::bpf_insn *new_insn = new libbpf::bpf_insn[new_len];
    ssize_t delta = (ssize_t)len - (ssize_t)orig_len;

    // 1. Copy instructions before position, updating forward calls crossing the range
    for (size_t i = 0; i < position; i++) {
        new_insn[i] = old_data[i];
        if (insn_is_subprog_call(&new_insn[i])) {
            if (i + new_insn[i].imm > position) {
                new_insn[i].imm += delta;
            }
        }
    }

    // 2. Insert new filter instructions at position
    std::memcpy(&new_insn[position], data, len * sizeof(libbpf::bpf_insn));

    // 3. Copy instructions after position + orig_len, updating backward calls crossing the range
    for (size_t i = position + orig_len; i < old_len; i++) {
        size_t new_idx = i - orig_len + len;
        new_insn[new_idx] = old_data[i];
        if (insn_is_subprog_call(&new_insn[new_idx])) {
            if (i + new_insn[new_idx].imm < position) {
                new_insn[new_idx].imm -= delta;
            }
        }
    }

    int ret = libbpf::bpf_program__set_insns(prog, new_insn, new_len);
    delete[] new_insn;
    return ret;
}