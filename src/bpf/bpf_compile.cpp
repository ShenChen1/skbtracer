#include <string>
#include <vector>
#include <spdlog/spdlog.h>

#include "bpf-common.h"

namespace cbpf {
extern "C" {
#include <linux/filter.h>
#include <pcap/pcap.h>
}
} /* namespace cbpf */

extern "C" {
int bpf_convert_filter(cbpf::sock_filter *prog, int len,
                       libbpf::bpf_insn *new_prog, int *new_len);
}

static std::pair<int, cbpf::sock_fprog> compile_cbpf_filter(const std::string &filter_str, bool l3)
{
    constexpr int MAXIMUM_SNAPLEN = 262144;
    int err = 0;
    cbpf::sock_fprog sf = { 0, NULL };
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
    sf.filter = new cbpf::sock_filter[sf.len];
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

std::tuple<int, libbpf::bpf_insn *, size_t> bpfhelper::compile_ebpf_filter(const std::string &filter_str, bool l3)
{
    int err = 0;
    libbpf::bpf_insn *ebpf = NULL;
    int ebpf_len = 0;

    auto [ret, cbpf] = compile_cbpf_filter(filter_str, l3);
    if (ret) {
        err = ret;
        goto end;
    }

    /* 1st pass: calculate the eBPF program length */
    err = bpf_convert_filter(cbpf.filter, cbpf.len, NULL, &ebpf_len);
    if (err) {
        spdlog::error("cannot get eBPF length");
        goto end;
    }

    spdlog::info("prog len cBPF=%u -> eBPF=%u", cbpf.len, ebpf_len);
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

end:
    delete[] cbpf.filter;
    return { err, ebpf, ebpf_len };
}
