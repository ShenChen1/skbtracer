#include <arpa/inet.h>
#include <cassert>
#include <iostream>
#include <netinet/in.h>
#include <spdlog/fmt/fmt.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "dev_cache.h"
#include "meta_output.h"
#include "output.h"
#include "time_output.h"
#include "tuple_output.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

static void test_protocol_name()
{
    assert(std::string(Output::get_protocol_name(IPPROTO_TCP)) == "TCP");
    assert(std::string(Output::get_protocol_name(IPPROTO_UDP)) == "UDP");
    assert(std::string(Output::get_protocol_name(IPPROTO_ICMP)) == "ICMP");
    assert(std::string(Output::get_protocol_name(IPPROTO_ICMPV6)) == "ICMP6");
    assert(std::string(Output::get_protocol_name(0)) == "-");
    assert(std::string(Output::get_protocol_name(254)) == "-");
    std::cout << "[PASS] test_protocol_name" << std::endl;
}

static void test_protocol_has_ports()
{
    assert(Output::protocol_has_ports(IPPROTO_TCP) == true);
    assert(Output::protocol_has_ports(IPPROTO_UDP) == true);
    assert(Output::protocol_has_ports(IPPROTO_ICMP) == false);
    assert(Output::protocol_has_ports(IPPROTO_ICMPV6) == false);
    assert(Output::protocol_has_ports(0) == false);
    std::cout << "[PASS] test_protocol_has_ports" << std::endl;
}

static void test_format_tuple_tcp()
{
    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IP;
    inet_pton(AF_INET, "192.168.1.10", &event.tuple.saddr.v4addr);
    inet_pton(AF_INET, "10.0.0.1", &event.tuple.daddr.v4addr);
    event.tuple.l4_proto = IPPROTO_TCP;
    event.tuple.sport = htons(12345);
    event.tuple.dport = htons(80);

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "192.168.1.10:12345 -> 10.0.0.1:80 [TCP]");
    std::cout << "[PASS] test_format_tuple_tcp" << std::endl;
}

static void test_format_tuple_icmp()
{
    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IP;
    inet_pton(AF_INET, "1.1.1.1", &event.tuple.saddr.v4addr);
    inet_pton(AF_INET, "8.8.8.8", &event.tuple.daddr.v4addr);
    event.tuple.l4_proto = IPPROTO_ICMP;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "1.1.1.1 -> 8.8.8.8 [ICMP]");
    std::cout << "[PASS] test_format_tuple_icmp" << std::endl;
}

static void test_format_tuple_ipv6_tcp()
{
    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IPV6;
    inet_pton(AF_INET6, "2001:db8::1", &event.tuple.saddr.v6addr);
    inet_pton(AF_INET6, "2001:db8::2", &event.tuple.daddr.v6addr);
    event.tuple.l4_proto = IPPROTO_TCP;
    event.tuple.sport = htons(12345);
    event.tuple.dport = htons(80);

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "[2001:db8::1]:12345 -> [2001:db8::2]:80 [TCP]");
    std::cout << "[PASS] test_format_tuple_ipv6_tcp" << std::endl;
}

static void test_format_tuple_ipv6_udp()
{
    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IPV6;
    inet_pton(AF_INET6, "fe80::1", &event.tuple.saddr.v6addr);
    inet_pton(AF_INET6, "fe80::2", &event.tuple.daddr.v6addr);
    event.tuple.l4_proto = IPPROTO_UDP;
    event.tuple.sport = htons(5353);
    event.tuple.dport = htons(5353);

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "[fe80::1]:5353 -> [fe80::2]:5353 [UDP]");
    std::cout << "[PASS] test_format_tuple_ipv6_udp" << std::endl;
}

static void test_format_tuple_ipv6_icmp6()
{
    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IPV6;
    inet_pton(AF_INET6, "2001:db8::1", &event.tuple.saddr.v6addr);
    inet_pton(AF_INET6, "2001:db8::2", &event.tuple.daddr.v6addr);
    event.tuple.l4_proto = IPPROTO_ICMPV6;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "2001:db8::1 -> 2001:db8::2 [ICMP6]");
    std::cout << "[PASS] test_format_tuple_ipv6_icmp6" << std::endl;
}

static void test_format_tuple_empty()
{
    skb_event event = {};
    event.tuple.l4_proto = 0;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "-");
    std::cout << "[PASS] test_format_tuple_empty" << std::endl;
}

static void test_format_tuple_with_ifindex()
{
    static_assert(sizeof(decltype(skb_event().meta.ifindex)) == 4, "ifindex must be 32-bit uint32_t");

    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IP;
    inet_pton(AF_INET, "127.0.0.1", &event.tuple.saddr.v4addr);
    inet_pton(AF_INET, "127.0.0.1", &event.tuple.daddr.v4addr);
    event.tuple.l4_proto = IPPROTO_TCP;
    event.tuple.sport = htons(80);
    event.tuple.dport = htons(8080);
    event.meta.ifindex = 1; // Loopback interface

    // Tuple output no longer appends dev suffix
    std::string tuple = Output::format_tuple(event);
    assert(tuple == "127.0.0.1:80 -> 127.0.0.1:8080 [TCP]");
    std::cout << "[PASS] test_format_tuple_with_ifindex" << std::endl;
}

static void test_format_tuple_cross_netns()
{
    static_assert(sizeof(decltype(skb_event().meta.netns)) == 4, "netns must be 32-bit uint32_t");

    skb_event event = {};
    event.tuple.l3_proto = ETH_P_IP;
    inet_pton(AF_INET, "10.0.0.1", &event.tuple.saddr.v4addr);
    inet_pton(AF_INET, "10.0.0.2", &event.tuple.daddr.v4addr);
    event.tuple.l4_proto = IPPROTO_TCP;
    event.tuple.sport = htons(1234);
    event.tuple.dport = htons(5678);
    event.meta.netns = 12345678U; // A foreign netns
    event.meta.ifindex = 10;

    // 1. Tuple itself outputs clean five-tuple without dev
    std::string tuple1 = Output::format_tuple(event);
    assert(tuple1 == "10.0.0.1:1234 -> 10.0.0.2:5678 [TCP]");

    // 2. Dev name resolution and formatting across netns
    assert(Output::resolve_dev_name(12345678U, 10) == "");
    assert(Output::format_iface(12345678U, 10) == "10");

    Output::register_ifname(12345678U, 10, "veth_target");
    assert(Output::resolve_dev_name(12345678U, 10) == "veth_target");
    assert(Output::format_iface(12345678U, 10) == "veth_target:10");

    std::cout << "[PASS] test_format_tuple_cross_netns" << std::endl;
}

static void test_format_tuple_direct_tuple_and_meta()
{
    skb_tuple tuple = {};
    skb_meta meta = {};

    tuple.l3_proto = ETH_P_IP;
    inet_pton(AF_INET, "172.16.0.1", &tuple.saddr.v4addr);
    inet_pton(AF_INET, "172.16.0.2", &tuple.daddr.v4addr);
    tuple.l4_proto = IPPROTO_UDP;
    tuple.sport = htons(5000);
    tuple.dport = htons(6000);

    meta.ifindex = 1; // lo
    meta.netns = 0;

    std::string res = Output::format_tuple(tuple, meta);
    assert(res == "172.16.0.1:5000 -> 172.16.0.2:6000 [UDP]");
    std::cout << "[PASS] test_format_tuple_direct_tuple_and_meta" << std::endl;
}

static void test_format_meta_basic()
{
    skb_meta meta = {};
    meta.netns = 4026531999U;
    meta.ifindex = 0;
    meta.mtu = 1500;
    meta.len = 128;
    meta.proto = htons(0x0800);
    meta.mark = 0x20;

    std::string expected = fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} 0x{:<6x}",
                                      4026531999U, "0", 1500, 128, "0x0800", 0x20);
    std::string meta_str = MetaOutput::format_meta(meta);
    assert(meta_str == expected);

    skb_event event = {};
    event.meta = meta;
    assert(Output::format_meta(event) == expected);
    std::cout << "[PASS] test_format_meta_basic" << std::endl;
}

static void test_format_meta_with_dev()
{
    skb_meta meta = {};
    meta.netns = 0;
    meta.ifindex = 1; // loopback
    meta.mtu = 65535;
    meta.len = 64;
    meta.proto = htons(0x86dd);
    meta.mark = 0x0;

    std::string expected = fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} 0x{:<6x}",
                                      0, "lo:1", 65535, 64, "0x86dd", 0);
    std::string meta_str = Output::format_meta(meta);
    assert(meta_str == expected);
    std::cout << "[PASS] test_format_meta_with_dev" << std::endl;
}

static void test_format_meta_unresolved_ifindex()
{
    skb_meta meta = {};
    meta.netns = 99999999U;
    meta.ifindex = 42;
    meta.mtu = 1500;
    meta.len = 256;
    meta.proto = htons(0x0800);
    meta.mark = 0x5;

    std::string expected = fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} 0x{:<6x}",
                                      99999999U, "42", 1500, 256, "0x0800", 0x5);
    std::string meta_str = Output::format_meta(meta);
    assert(meta_str == expected);
    std::cout << "[PASS] test_format_meta_unresolved_ifindex" << std::endl;
}

static void test_format_meta_header()
{
    std::string expected = fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} {:<8}",
                                      "NETNS", "IFACE", "MTU", "LEN", "PROTO", "MARK");
    assert(Output::format_meta_header() == expected);
    std::cout << "[PASS] test_format_meta_header" << std::endl;
}

static void test_output_modes_orchestration()
{
    skb_event event = {};
    event.ts = 1000000000ULL;
    event.cpu_id = 1;
    event.pid = 1234;
    event.skb_addr = 0xffff888001234500ULL;
    event.addr = 0xffffffff81234567ULL;
    event.meta.len = 100;
    event.meta.mtu = 1500;
    event.meta.ifindex = 1;

    // 1. None enabled
    {
        Options::args args{};
        args.output_meta = false;
        args.output_tuple = false;
        Output out;
        assert(out.init(args) == 0);
        assert(out.print_header() == 0);
        assert(out.print_entry(event) == 0);
    }

    // 2. Only Meta
    {
        Options::args args{};
        args.output_meta = true;
        args.output_tuple = false;
        Output out;
        assert(out.init(args) == 0);
        assert(out.print_header() == 0);
        assert(out.print_entry(event) == 0);
    }

    // 3. Only Tuple
    {
        Options::args args{};
        args.output_meta = false;
        args.output_tuple = true;
        Output out;
        assert(out.init(args) == 0);
        assert(out.print_header() == 0);
        assert(out.print_entry(event) == 0);
    }

    // 4. Both Meta and Tuple
    {
        Options::args args{};
        args.output_meta = true;
        args.output_tuple = true;
        Output out;
        assert(out.init(args) == 0);
        assert(out.print_header() == 0);
        assert(out.print_entry(event) == 0);
    }

    std::cout << "[PASS] test_output_modes_orchestration" << std::endl;
}

static void test_format_proc()
{
    assert(Output::format_proc(0) == "0/swapper");
    assert(Output::format_proc(9999999) == "9999999/9999999");

    uint32_t my_pid = static_cast<uint32_t>(getpid());
    std::string proc = Output::format_proc(my_pid);
    assert(proc.find(std::to_string(my_pid) + "/") == 0);
    assert(proc.length() > std::to_string(my_pid).length() + 1);
    std::cout << "[PASS] test_format_proc: " << proc << std::endl;
}

static void test_time_output_parsing_and_formatting()
{
    // 1. Parsing modes
    bool ok = false;
    assert(TimeOutput::parse_mode("none", ok) == TimestampMode::NONE && ok);
    assert(TimeOutput::parse_mode("", ok) == TimestampMode::NONE && ok);
    assert(TimeOutput::parse_mode("current", ok) == TimestampMode::CURRENT && ok);
    assert(TimeOutput::parse_mode("relative", ok) == TimestampMode::RELATIVE && ok);
    assert(TimeOutput::parse_mode("absolute", ok) == TimestampMode::ABSOLUTE && ok);

    TimeOutput::parse_mode("invalid", ok);
    assert(!ok);

    // 2. Format headers
    assert(TimeOutput::format_header(TimestampMode::NONE) == "");
    assert(TimeOutput::format_header(TimestampMode::RELATIVE) == fmt::format("{:<10}", "TIME(s)"));
    assert(TimeOutput::format_header(TimestampMode::CURRENT) == fmt::format("{:<12}", "TIME"));
    assert(TimeOutput::format_header(TimestampMode::ABSOLUTE) == fmt::format("{:<23}", "TIME"));

    // 3. Format time relative
    uint64_t start_ts = 1000000000ULL;
    uint64_t event_ts = 2500000000ULL;
    std::string rel_str = TimeOutput::format_time(TimestampMode::RELATIVE, event_ts, start_ts);
    assert(rel_str == fmt::format("{:<10.6f}", 1.5));
    assert(rel_str.length() == 10);

    // 4. Format time current & absolute
    std::string cur_str = TimeOutput::format_time(TimestampMode::CURRENT, event_ts, start_ts);
    assert(cur_str.length() == 12);
    assert(cur_str[2] == ':' && cur_str[5] == ':' && cur_str[8] == '.');

    std::string abs_str = TimeOutput::format_time(TimestampMode::ABSOLUTE, event_ts, start_ts);
    assert(abs_str.length() == 23);
    assert(abs_str[4] == '-' && abs_str[7] == '-' && abs_str[10] == 'T');

    assert(TimeOutput::format_time(TimestampMode::NONE, event_ts, start_ts) == "");

    std::cout << "[PASS] test_time_output_parsing_and_formatting" << std::endl;
}

static void test_output_with_timestamps()
{
    skb_event event = {};
    event.ts = 1000000000ULL;
    event.cpu_id = 2;
    event.pid = 4321;
    event.skb_addr = 0xffff888001234500ULL;
    event.addr = 0xffffffff81234567ULL;

    const std::vector<std::string> modes = { "none", "relative", "current", "absolute" };
    for (const auto &m : modes) {
        Options::args args{};
        args.timestamp = m;
        args.output_meta = true;
        args.output_tuple = true;

        Output out;
        assert(out.init(args) == 0);
        assert(out.print_header() == 0);
        assert(out.print_entry(event) == 0);
    }

    std::cout << "[PASS] test_output_with_timestamps" << std::endl;
}

int main()
{
    std::cout << "Running Output unit tests..." << std::endl;
    test_protocol_name();
    test_protocol_has_ports();
    test_format_tuple_tcp();
    test_format_tuple_icmp();
    test_format_tuple_ipv6_tcp();
    test_format_tuple_ipv6_udp();
    test_format_tuple_ipv6_icmp6();
    test_format_tuple_empty();
    test_format_tuple_with_ifindex();
    test_format_tuple_cross_netns();
    test_format_tuple_direct_tuple_and_meta();
    test_format_meta_basic();
    test_format_meta_with_dev();
    test_format_meta_unresolved_ifindex();
    test_format_meta_header();
    test_format_proc();
    test_output_modes_orchestration();
    test_time_output_parsing_and_formatting();
    test_output_with_timestamps();
    std::cout << "All Output unit tests passed successfully!" << std::endl;
    return 0;
}
