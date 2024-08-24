#include <string>
#include <vector>
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
int get_insns_for_prepare_replace_insns(libbpf::bpf_insn **data, int *len);
int get_insns_for_post_replace_insns(libbpf::bpf_insn **data, int *len);
int get_insns_for_replace_insns(libbpf::bpf_insn *origin, libbpf::bpf_insn **data, int *len);
int free_insns(libbpf::bpf_insn *data);
}

static std::pair<int, libbpf::sock_fprog> compile_cbpf_filter(const std::string &filter_str, bool l3)
{
    constexpr int MAXIMUM_SNAPLEN = 262144;
    int err = 0;
    libbpf::sock_fprog sf = { 0, NULL };
    cbpf::bpf_program bf = { 0, NULL };
    cbpf::pcap_t *pcap;
    int linktype = l3 ? DLT_RAW : DLT_EN10MB;

    pcap = cbpf::pcap_open_dead(linktype, MAXIMUM_SNAPLEN);
    if (!pcap) {
        spdlog::error("can not open pcap");
        return { -EFAULT, sf };
    }

    if (cbpf::pcap_compile(pcap, &bf, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        spdlog::error("pcap filter string not valid (%s)", cbpf::pcap_geterr(pcap));
        err = -EINVAL;
        goto end;
    }

    sf.len = bf.bf_len;
    sf.filter = new libbpf::sock_filter[sf.len];
    if (!sf.filter) {
        spdlog::error("failed to allocate memory for sock_filter");
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

static bool insn_is_ld_abs(const libbpf::bpf_insn *insn)
{
    return BPF_CLASS(insn->code) == BPF_LD &&
          (BPF_MODE(insn->code) == BPF_ABS ||
           BPF_MODE(insn->code) == BPF_IND);
}

static std::tuple<int, libbpf::bpf_insn *, size_t> adjust_ebpf_filter(libbpf::bpf_insn *insn, size_t len)
{
    int err = 0;
    libbpf::bpf_insn *insn_seg = NULL;
    int insn_seg_len = 0;
    std::vector<libbpf::bpf_insn> insns_vec = {};

    err = get_insns_for_prepare_replace_insns(&insn_seg, &insn_seg_len);
    if (err || !insn_seg || !insn_seg_len) {
        return { -ENOMEM, NULL, 0 };
    }
    insns_vec.insert(insns_vec.end(), insn_seg, insn_seg + insn_seg_len);
    free_insns(insn_seg);

    for (size_t i = 0; i < len; i++) {
        if (!insn_is_ld_abs(&insn[i])) {
            insns_vec.push_back(insn[i]);
            continue;
        }

        err = get_insns_for_replace_insns(&insn[i], &insn_seg, &insn_seg_len);
        if (err || !insn_seg || !insn_seg_len) {
            continue;
        }
        insns_vec.insert(insns_vec.end(), insn_seg, insn_seg + insn_seg_len);
        free_insns(insn_seg);
    }

    err = get_insns_for_post_replace_insns(&insn_seg, &insn_seg_len);
    if (err || !insn_seg || !insn_seg_len) {
        return { -ENOMEM, NULL, 0 };
    }
    insns_vec.insert(insns_vec.end(), insn_seg, insn_seg + insn_seg_len);
    free_insns(insn_seg);

    auto new_len = insns_vec.size();
    auto new_insn = new libbpf::bpf_insn[new_len];
    std::copy(insns_vec.begin(), insns_vec.end(), new_insn);

    return { 0, new_insn, new_len };
}

std::tuple<int, libbpf::bpf_insn *, size_t> pcap2bpf::compile_ebpf_filter(const std::string &filter_str, bool l3)
{
    int err = 0;
    libbpf::bpf_insn *ebpf = NULL, *new_ebpf = NULL;
    int ebpf_len = 0, new_ebpf_len = 0;

    if (filter_str.empty()) {
        get_insns_for_filter_empty(&ebpf, &ebpf_len);
        return { 0, ebpf, ebpf_len };
    }

    auto [ret, cbpf] = compile_cbpf_filter(filter_str, l3);
    if (ret) {
        spdlog::error("cannot compile cBPF filter");
        err = ret;
        goto end;
    }

    /* 1st pass: calculate the eBPF program length */
    err = bpf_convert_filter(cbpf.filter, cbpf.len, NULL, &ebpf_len);
    if (err) {
        spdlog::error("cannot get eBPF length");
        goto end;
    }

    spdlog::info("prog len cBPF={} -> eBPF={}", cbpf.len, ebpf_len);
    ebpf = new libbpf::bpf_insn[ebpf_len];
    if (!ebpf) {
        spdlog::error("failed to allocate memory for eBPF instructions");
        err = -ENOMEM;
        goto end;
    }

    /* 2nd pass: remap cBPF to eBPF instructions */
    err = bpf_convert_filter(cbpf.filter, cbpf.len, ebpf, &ebpf_len);
    if (err) {
        spdlog::error("cannot convert cBPF to eBPF");
        goto end;
    }

    /* 3rd pass: adjust ebpf */
    std::tie(ret, new_ebpf, new_ebpf_len) = adjust_ebpf_filter(ebpf, ebpf_len);
    if (ret) {
        spdlog::error("cannot adjust eBPF");
        err = ret;
        goto end;
    }
    spdlog::info("adjust eBPF={} -> {}", ebpf_len, new_ebpf_len);
    delete[] ebpf;
    ebpf = new_ebpf;
    ebpf_len = new_ebpf_len;

end:
    delete[] cbpf.filter;
    return { err, ebpf, ebpf_len };
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

int pcap2bpf::inject_ebpf_filter(libbpf::bpf_program *prog, size_t position, const libbpf::bpf_insn *data, size_t len)
{
    auto old_len = libbpf::bpf_program__insn_cnt(prog);
    auto old_data = libbpf::bpf_program__insns(prog);

    auto new_len = old_len + len;
    libbpf::bpf_insn *new_insn = new libbpf::bpf_insn[new_len];

    for (size_t i = 0; i < position; i++) {
        new_insn[i] = old_data[i];
        if (!insn_is_subprog_call(&new_insn[i])) {
            continue;
        }

        if (i + new_insn[i].imm > position) {
            new_insn[i].imm += len;
        }
    }

    std::memcpy(&new_insn[position], data, len * sizeof(libbpf::bpf_insn));
    std::memcpy(&new_insn[position + len], &old_data[position], (old_len - position) * sizeof(libbpf::bpf_insn));
    return libbpf::bpf_program__set_insns(prog, new_insn, new_len);
}