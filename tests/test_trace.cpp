#include <cassert>
#include <cerrno>
#include <cstdint>
#include <iostream>
#include <vector>

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

    std::vector<libbpf::bpf_insn> dummy_insns(2);
    dummy_insns[0].code = BPF_ALU64 | BPF_MOV | BPF_K;
    dummy_insns[0].dst_reg = libbpf::BPF_REG_0;
    dummy_insns[0].imm = 1;
    dummy_insns[1].code = BPF_JMP | BPF_EXIT;

    // Happy path: replace first instruction with two dummy instructions
    int ret = pcap2bpf::inject_ebpf_filter(prog, 0, 1, dummy_insns);
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

    std::vector<libbpf::bpf_insn> dummy_insns(1);
    dummy_insns[0].code = BPF_ALU64 | BPF_MOV | BPF_K;
    dummy_insns[0].dst_reg = libbpf::BPF_REG_0;
    dummy_insns[0].imm = 1;

    // Failure path: position out of bounds
    int ret = pcap2bpf::inject_ebpf_filter(prog, insn_cnt + 10, 7, dummy_insns);
    assert(ret == -EINVAL);

    libbpf::skbtracer_bpf__destroy(skel);
    std::cout << "[PASS] test_inject_ebpf_filter_bounds_failure" << std::endl;
}

static void test_vlan_qinq_l3_offset_detection()
{
    struct MockVlanHdr {
        uint16_t tci;
        uint16_t encapsulated_proto;
    } __attribute__((packed));

    struct MockIpHdr {
        uint8_t ihl : 4;
        uint8_t version : 4;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    } __attribute__((packed));

    auto is_vlan = [](uint16_t proto) -> bool {
        return proto == __builtin_bswap16(0x8100) ||
               proto == __builtin_bswap16(0x88a8);
    };

    auto calc_l3_offset = [&](uint16_t initial_proto, uint16_t initial_off, const uint8_t *buf, size_t buf_len) -> uint16_t {
        uint16_t off = initial_off;
        uint16_t proto = initial_proto;
        for (int i = 0; i < 2; i++) {
            if (!is_vlan(proto)) {
                break;
            }
            if (off + sizeof(MockVlanHdr) > buf_len) {
                break;
            }
            auto vhdr = reinterpret_cast<const MockVlanHdr *>(buf + off);
            off += sizeof(MockVlanHdr);
            proto = vhdr->encapsulated_proto;
        }

        return off;
    };

    // 1. Happy path: Plain IPv4 (no VLAN)
    {
        uint8_t pkt[sizeof(MockIpHdr)]{};
        auto ip = reinterpret_cast<MockIpHdr *>(pkt);
        ip->version = 4;
        ip->ihl = 5;
        ip->protocol = 6; // TCP
        uint16_t off = calc_l3_offset(__builtin_bswap16(0x0800), 0, pkt, sizeof(pkt));
        assert(off == 0);
        assert(reinterpret_cast<MockIpHdr *>(pkt + off)->version == 4);
    }

    // 2. Happy path: Single VLAN (802.1Q, 0x8100)
    {
        uint8_t pkt[sizeof(MockVlanHdr) + sizeof(MockIpHdr)]{};
        auto vlan = reinterpret_cast<MockVlanHdr *>(pkt);
        vlan->tci = __builtin_bswap16(100);
        vlan->encapsulated_proto = __builtin_bswap16(0x0800);
        auto ip = reinterpret_cast<MockIpHdr *>(pkt + sizeof(MockVlanHdr));
        ip->version = 4;
        ip->ihl = 5;
        ip->protocol = 17; // UDP

        uint16_t off = calc_l3_offset(__builtin_bswap16(0x8100), 0, pkt, sizeof(pkt));
        assert(off == sizeof(MockVlanHdr));
        assert(reinterpret_cast<MockIpHdr *>(pkt + off)->version == 4);
        assert(reinterpret_cast<MockIpHdr *>(pkt + off)->protocol == 17);
    }

    // 3. Happy path: QinQ (802.1ad 0x88A8 outer + 802.1Q 0x8100 inner)
    {
        uint8_t pkt[2 * sizeof(MockVlanHdr) + sizeof(MockIpHdr)]{};
        auto outer_vlan = reinterpret_cast<MockVlanHdr *>(pkt);
        outer_vlan->tci = __builtin_bswap16(200);
        outer_vlan->encapsulated_proto = __builtin_bswap16(0x8100);

        auto inner_vlan = reinterpret_cast<MockVlanHdr *>(pkt + sizeof(MockVlanHdr));
        inner_vlan->tci = __builtin_bswap16(100);
        inner_vlan->encapsulated_proto = __builtin_bswap16(0x0800);

        auto ip = reinterpret_cast<MockIpHdr *>(pkt + 2 * sizeof(MockVlanHdr));
        ip->version = 4;
        ip->ihl = 5;
        ip->protocol = 1; // ICMP

        uint16_t off = calc_l3_offset(__builtin_bswap16(0x88a8), 0, pkt, sizeof(pkt));
        assert(off == 2 * sizeof(MockVlanHdr));
        assert(reinterpret_cast<MockIpHdr *>(pkt + off)->version == 4);
        assert(reinterpret_cast<MockIpHdr *>(pkt + off)->protocol == 1);
    }

    // 4. Failure path: Truncated packet buffer
    {
        uint8_t pkt[2]{}; // Less than sizeof(MockVlanHdr)
        uint16_t off = calc_l3_offset(__builtin_bswap16(0x8100), 0, pkt, sizeof(pkt));
        assert(off == 0); // Must not advance beyond available buffer
    }

    std::cout << "[PASS] test_vlan_qinq_l3_offset_detection" << std::endl;
}

int main()
{
    std::cout << "Running trace unit and regression tests..." << std::endl;
    test_inject_ebpf_filter_success();
    test_inject_ebpf_filter_bounds_failure();
    test_vlan_qinq_l3_offset_detection();
    std::cout << "All trace unit and regression tests passed successfully!" << std::endl;
    return 0;
}
