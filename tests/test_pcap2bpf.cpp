#include <cassert>
#include <iostream>
#include <string>

#include "pcap2bpf.h"

static void test_empty_filter()
{
    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("", false);
    assert(err == 0);
    assert(insns != nullptr);
    assert(len == 2);
    delete[] insns;
    std::cout << "[PASS] test_empty_filter" << std::endl;
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
    test_valid_filters();
    test_l3_filter();
    test_invalid_filter_syntax();
    std::cout << "All pcap2bpf unit tests passed successfully!" << std::endl;
    return 0;
}
