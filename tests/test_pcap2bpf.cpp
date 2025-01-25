#include <cassert>
#include <iostream>
#include <string>

#include "pcap2bpf.h"

extern "C" {
int get_insns_for_filter_empty(libbpf::bpf_insn *data, int *len);
}

static void test_empty_filter()
{
    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("", false);
    assert(err == 0);
    assert(insns != nullptr);
    assert(len == 2);
    // Verify default pass instructions:
    // 1: r0 = 1
    // 2: exit
    assert(insns[0].code == (BPF_ALU64 | BPF_MOV | BPF_K));
    assert(insns[0].dst_reg == libbpf::BPF_REG_0);
    assert(insns[0].imm == 1);
    assert(insns[1].code == (BPF_JMP | BPF_EXIT));
    delete[] insns;
    std::cout << "[PASS] test_empty_filter" << std::endl;
}

static void test_get_insns_for_filter_empty_boundaries()
{
    // Test null len pointer
    assert(get_insns_for_filter_empty(nullptr, nullptr) == -EINVAL);

    // Test query len with null data
    int len = 0;
    assert(get_insns_for_filter_empty(nullptr, &len) == 0);
    assert(len == 2);

    // Test buffer too small
    len = 1;
    libbpf::bpf_insn small_buf[1];
    assert(get_insns_for_filter_empty(small_buf, &len) == -EINVAL);

    // Test normal fill
    len = 2;
    libbpf::bpf_insn valid_buf[2];
    assert(get_insns_for_filter_empty(valid_buf, &len) == 0);
    assert(len == 2);
    std::cout << "[PASS] test_get_insns_for_filter_empty_boundaries" << std::endl;
}

static void test_valid_filters()
{
    const std::vector<std::string> valid_cases = {
        "icmp",        "tcp and port 80", "udp and src port 53",         "host 192.168.1.1",     "ip proto 6 and dst port 443", "ip6", "icmp6",
        "tcp and ip6", "udp and ip6",     "ip6 proto 6 and dst port 80", "ip6 host 2001:db8::1",
    };

    for (const auto &filter : valid_cases) {
        auto [err, insns, len] = pcap2bpf::compile_ebpf_filter(filter, false);
        assert(err == 0);
        assert(insns != nullptr);
        assert(len > 0);
        delete[] insns;
        std::cout << "[PASS] test_valid_filter: " << filter << " (len=" << len << ")" << std::endl;
    }
}

static void test_l3_filter()
{
    const std::vector<std::string> l3_cases = {
        "ip and tcp port 80", "ip6", "icmp6", "tcp and ip6", "ip6 proto 6 and dst port 80",
    };

    for (const auto &filter : l3_cases) {
        auto [err, insns, len] = pcap2bpf::compile_ebpf_filter(filter, true);
        assert(err == 0);
        assert(insns != nullptr);
        assert(len > 0);
        delete[] insns;
        std::cout << "[PASS] test_l3_filter: " << filter << " (len=" << len << ")" << std::endl;
    }
}

static void test_invalid_filter_syntax()
{
    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("invalid syntax &&& @@@", false);
    assert(err != 0);
    assert(insns == nullptr);
    assert(len == 0);
    std::cout << "[PASS] test_invalid_filter_syntax (expected error=" << err << ")" << std::endl;
}

int main()
{
    std::cout << "Running pcap2bpf unit tests..." << std::endl;
    test_empty_filter();
    test_get_insns_for_filter_empty_boundaries();
    test_valid_filters();
    test_l3_filter();
    test_invalid_filter_syntax();
    std::cout << "All pcap2bpf unit tests passed successfully!" << std::endl;
    return 0;
}
