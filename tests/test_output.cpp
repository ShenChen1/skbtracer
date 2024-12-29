#include <arpa/inet.h>
#include <cassert>
#include <iostream>
#include <netinet/in.h>
#include <string>

#include "output.h"

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
    inet_pton(AF_INET, "192.168.1.10", &event.saddr.v4addr);
    inet_pton(AF_INET, "10.0.0.1", &event.daddr.v4addr);
    event.protocol = IPPROTO_TCP;
    event.sport = 12345;
    event.dport = 80;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "192.168.1.10:12345 -> 10.0.0.1:80 [TCP]");
    std::cout << "[PASS] test_format_tuple_tcp" << std::endl;
}

static void test_format_tuple_icmp()
{
    skb_event event = {};
    inet_pton(AF_INET, "1.1.1.1", &event.saddr.v4addr);
    inet_pton(AF_INET, "8.8.8.8", &event.daddr.v4addr);
    event.protocol = IPPROTO_ICMP;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "1.1.1.1 -> 8.8.8.8 [ICMP]");
    std::cout << "[PASS] test_format_tuple_icmp" << std::endl;
}

static void test_format_tuple_ipv6_tcp()
{
    skb_event event = {};
    event.ip_version = 6;
    inet_pton(AF_INET6, "2001:db8::1", &event.saddr.v6addr);
    inet_pton(AF_INET6, "2001:db8::2", &event.daddr.v6addr);
    event.protocol = IPPROTO_TCP;
    event.sport = 12345;
    event.dport = 80;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "[2001:db8::1]:12345 -> [2001:db8::2]:80 [TCP]");
    std::cout << "[PASS] test_format_tuple_ipv6_tcp" << std::endl;
}

static void test_format_tuple_ipv6_udp()
{
    skb_event event = {};
    event.ip_version = 6;
    inet_pton(AF_INET6, "fe80::1", &event.saddr.v6addr);
    inet_pton(AF_INET6, "fe80::2", &event.daddr.v6addr);
    event.protocol = IPPROTO_UDP;
    event.sport = 5353;
    event.dport = 5353;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "[fe80::1]:5353 -> [fe80::2]:5353 [UDP]");
    std::cout << "[PASS] test_format_tuple_ipv6_udp" << std::endl;
}

static void test_format_tuple_ipv6_icmp6()
{
    skb_event event = {};
    event.ip_version = 6;
    inet_pton(AF_INET6, "2001:db8::1", &event.saddr.v6addr);
    inet_pton(AF_INET6, "2001:db8::2", &event.daddr.v6addr);
    event.protocol = IPPROTO_ICMPV6;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "2001:db8::1 -> 2001:db8::2 [ICMP6]");
    std::cout << "[PASS] test_format_tuple_ipv6_icmp6" << std::endl;
}

static void test_format_tuple_empty()
{
    skb_event event = {};
    event.protocol = 0;

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "-");
    std::cout << "[PASS] test_format_tuple_empty" << std::endl;
}

static void test_format_tuple_with_ifindex()
{
    static_assert(sizeof(decltype(skb_event().ifindex)) == 4, "ifindex must be 32-bit uint32_t");

    skb_event event = {};
    inet_pton(AF_INET, "127.0.0.1", &event.saddr.v4addr);
    inet_pton(AF_INET, "127.0.0.1", &event.daddr.v4addr);
    event.protocol = IPPROTO_TCP;
    event.sport = 80;
    event.dport = 8080;
    event.ifindex = 1; // Loopback interface

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "127.0.0.1:80 -> 127.0.0.1:8080 [TCP] dev:lo");
    std::cout << "[PASS] test_format_tuple_with_ifindex" << std::endl;
}

static void test_format_tuple_cross_netns()
{
    static_assert(sizeof(decltype(skb_event().netns)) == 4, "netns must be 32-bit uint32_t");

    skb_event event = {};
    inet_pton(AF_INET, "10.0.0.1", &event.saddr.v4addr);
    inet_pton(AF_INET, "10.0.0.2", &event.daddr.v4addr);
    event.protocol = IPPROTO_TCP;
    event.sport = 1234;
    event.dport = 5678;
    event.netns = 12345678U; // A foreign netns
    event.ifindex = 10;

    // 1. Without cached name for foreign netns, it should output numeric dev:if10 (never wrong host interface)
    std::string tuple1 = Output::format_tuple(event);
    assert(tuple1 == "10.0.0.1:1234 -> 10.0.0.2:5678 [TCP] dev:if10");

    // 2. With registered name for foreign netns, it should output dev:veth_target
    Output::register_ifname(12345678U, 10, "veth_target");
    std::string tuple2 = Output::format_tuple(event);
    assert(tuple2 == "10.0.0.1:1234 -> 10.0.0.2:5678 [TCP] dev:veth_target");

    std::cout << "[PASS] test_format_tuple_cross_netns" << std::endl;
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
    std::cout << "All Output unit tests passed successfully!" << std::endl;
    return 0;
}
