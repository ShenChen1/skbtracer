#include <arpa/inet.h>
#include <cassert>
#include <iostream>
#include <netinet/in.h>
#include <string>

#include "output.h"

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

    std::string tuple = Output::format_tuple(event);
    assert(tuple == "127.0.0.1:80 -> 127.0.0.1:8080 [TCP] dev:lo");
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

    // 1. Without cached name for foreign netns, it should output numeric dev:if10 (never wrong host interface)
    std::string tuple1 = Output::format_tuple(event);
    assert(tuple1 == "10.0.0.1:1234 -> 10.0.0.2:5678 [TCP] dev:if10");

    // 2. With registered name for foreign netns, it should output dev:veth_target
    Output::register_ifname(12345678U, 10, "veth_target");
    std::string tuple2 = Output::format_tuple(event);
    assert(tuple2 == "10.0.0.1:1234 -> 10.0.0.2:5678 [TCP] dev:veth_target");

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
    assert(res == "172.16.0.1:5000 -> 172.16.0.2:6000 [UDP] dev:lo");
    std::cout << "[PASS] test_format_tuple_direct_tuple_and_meta" << std::endl;
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
    std::cout << "All Output unit tests passed successfully!" << std::endl;
    return 0;
}
