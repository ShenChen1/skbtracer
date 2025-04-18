#include "tuple_output.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <spdlog/fmt/fmt.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

const char *TupleOutput::get_protocol_name(uint8_t protocol)
{
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_ICMPV6:
            return "ICMP6";
        default:
            return "-";
    }
}

bool TupleOutput::protocol_has_ports(uint8_t protocol)
{
    return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

static std::string format_ipv6_tuple(const skb_tuple &tuple, const char *proto_name)
{
    char s_ip[INET6_ADDRSTRLEN] = "-";
    char d_ip[INET6_ADDRSTRLEN] = "-";
    if (tuple.saddr.v6addr.d1 != 0 || tuple.saddr.v6addr.d2 != 0) {
        inet_ntop(AF_INET6, &tuple.saddr.v6addr, s_ip, sizeof(s_ip));
    }
    if (tuple.daddr.v6addr.d1 != 0 || tuple.daddr.v6addr.d2 != 0) {
        inet_ntop(AF_INET6, &tuple.daddr.v6addr, d_ip, sizeof(d_ip));
    }

    if (TupleOutput::protocol_has_ports(tuple.l4_proto)) {
        return fmt::format("[{}]:{} -> [{}]:{} [{}]", s_ip, ntohs(tuple.sport), d_ip, ntohs(tuple.dport), proto_name);
    }
    return fmt::format("{} -> {} [{}]", s_ip, d_ip, proto_name);
}

static std::string format_ipv4_tuple(const skb_tuple &tuple, const char *proto_name)
{
    char s_ip[INET_ADDRSTRLEN] = "-";
    char d_ip[INET_ADDRSTRLEN] = "-";
    if (tuple.saddr.v4addr) {
        struct in_addr sa = { .s_addr = tuple.saddr.v4addr };
        inet_ntop(AF_INET, &sa, s_ip, sizeof(s_ip));
    }
    if (tuple.daddr.v4addr) {
        struct in_addr da = { .s_addr = tuple.daddr.v4addr };
        inet_ntop(AF_INET, &da, d_ip, sizeof(d_ip));
    }

    if (TupleOutput::protocol_has_ports(tuple.l4_proto)) {
        return fmt::format("{}:{} -> {}:{} [{}]", s_ip, ntohs(tuple.sport), d_ip, ntohs(tuple.dport), proto_name);
    }
    return fmt::format("{} -> {} [{}]", s_ip, d_ip, proto_name);
}

std::string TupleOutput::format_tuple(const skb_tuple &tuple)
{
    if (tuple.l4_proto == 0) {
        return "-";
    }

    const char *proto_name = get_protocol_name(tuple.l4_proto);
    return (tuple.l3_proto == ETH_P_IPV6) ? format_ipv6_tuple(tuple, proto_name) : format_ipv4_tuple(tuple, proto_name);
}

std::string TupleOutput::format_tuple(const skb_tuple &tuple, const skb_meta &/*meta*/)
{
    return format_tuple(tuple);
}

std::string TupleOutput::format_tuple(const skb_event &event)
{
    return format_tuple(event.tuple);
}
