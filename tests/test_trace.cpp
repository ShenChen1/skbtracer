#include <cassert>
#include <cerrno>
#include <iostream>

#include "pcap2bpf.h"
#include "skbtracer.h"

extern "C" {
namespace libbpf {
#include "skbtracer.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
} // namespace libbpf
}

static void test_inject_ebpf_filter_success()
{
    auto skel = libbpf::skbtracer_bpf__open();
    assert(skel != nullptr);

    auto prog = skel->progs.kprobe_skb_1;
    assert(prog != nullptr);

    size_t orig_cnt = libbpf::bpf_program__insn_cnt(prog);
    assert(orig_cnt > 0);

    libbpf::bpf_insn dummy_insns[2]{};
    dummy_insns[0].code = BPF_ALU64 | BPF_MOV | BPF_K;
    dummy_insns[0].dst_reg = libbpf::BPF_REG_0;
    dummy_insns[0].imm = 1;
    dummy_insns[1].code = BPF_JMP | BPF_EXIT;

    // Happy path: replace first instruction with two dummy instructions
    int ret = pcap2bpf::inject_ebpf_filter(prog, 0, 1, dummy_insns, 2);
    assert(ret == 0);
    assert(libbpf::bpf_program__insn_cnt(prog) == orig_cnt + 1);

    libbpf::skbtracer_bpf__destroy(skel);
    std::cout << "[PASS] test_inject_ebpf_filter_success" << std::endl;
}

static void test_inject_ebpf_filter_bounds_failure()
{
    auto skel = libbpf::skbtracer_bpf__open();
    assert(skel != nullptr);

    auto prog = skel->progs.kprobe_skb_1;
    assert(prog != nullptr);

    size_t insn_cnt = libbpf::bpf_program__insn_cnt(prog);
    assert(insn_cnt > 0);

    libbpf::bpf_insn dummy_insn{};
    dummy_insn.code = BPF_ALU64 | BPF_MOV | BPF_K;
    dummy_insn.dst_reg = libbpf::BPF_REG_0;
    dummy_insn.imm = 1;

    // Failure path: position out of bounds
    int ret = pcap2bpf::inject_ebpf_filter(prog, insn_cnt + 10, 7, &dummy_insn, 1);
    assert(ret == -EINVAL);

    libbpf::skbtracer_bpf__destroy(skel);
    std::cout << "[PASS] test_inject_ebpf_filter_bounds_failure" << std::endl;
}

int main()
{
    std::cout << "Running trace unit and regression tests..." << std::endl;
    test_inject_ebpf_filter_success();
    test_inject_ebpf_filter_bounds_failure();
    std::cout << "All trace unit and regression tests passed successfully!" << std::endl;
    return 0;
}
