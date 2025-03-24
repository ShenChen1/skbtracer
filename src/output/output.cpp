#include "output.h"
#include "symdb.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include <mutex>
#include <sys/stat.h>
#include <unordered_map>

constexpr double NS_PER_SEC = 1e9;

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

static std::mutex s_comm_mutex;
static std::unordered_map<uint32_t, std::string> s_comm_cache;

static std::string resolve_comm(uint32_t pid)
{
    if (pid == 0) {
        return "swapper";
    }

    std::lock_guard<std::mutex> lock(s_comm_mutex);
    auto it = s_comm_cache.find(pid);
    if (it != s_comm_cache.end()) {
        return it->second;
    }

    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    FILE *f = fopen(comm_path.c_str(), "r");
    if (f) {
        char buf[64] = "";
        if (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            std::string name(buf);
            fclose(f);
            s_comm_cache[pid] = name;
            return name;
        }
        fclose(f);
    }

    std::string fallback = std::to_string(pid);
    s_comm_cache[pid] = fallback;
    return fallback;
}

static std::mutex s_ifname_mutex;
static std::unordered_map<uint64_t, std::string> s_ifname_cache;
static uint32_t s_current_netns_id = 0;

static uint64_t make_cache_key(uint32_t netns, uint32_t ifindex)
{
    return (static_cast<uint64_t>(netns) << 32) | ifindex;
}

Output::Output()
{
}

Output::~Output()
{
}

void Output::register_ifname(uint32_t netns, uint32_t ifindex, const std::string &ifname)
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    s_ifname_cache[make_cache_key(netns, ifindex)] = ifname;
}

void Output::clear_ifname_cache()
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    s_ifname_cache.clear();
    s_current_netns_id = 0;
}

std::string Output::resolve_dev_name(uint32_t netns, uint32_t ifindex)
{
    if (ifindex == 0) {
        return "";
    }

    std::lock_guard<std::mutex> lock(s_ifname_mutex);

    // 1. Check if cached for specific netns or netns 0
    auto it = s_ifname_cache.find(make_cache_key(netns, ifindex));
    if (it != s_ifname_cache.end()) {
        return it->second;
    }

    // 2. If netns is current netns or 0, query local namespace
    if (netns == 0 || (s_current_netns_id != 0 && netns == s_current_netns_id)) {
        char buf[IF_NAMESIZE] = "";
        if (if_indextoname(ifindex, buf)) {
            std::string name(buf);
            s_ifname_cache[make_cache_key(netns, ifindex)] = name;
            return name;
        }
    }

    // 3. Fallback to numeric index format: if<index>
    return "if" + std::to_string(ifindex);
}

int Output::init(const Options::args &args)
{
    output_meta = args.output_skb;
    output_tuple = true;
    start_ts = 0;

    struct stat st{};
    if (stat("/proc/self/ns/net", &st) == 0) {
        s_current_netns_id = static_cast<uint32_t>(st.st_ino);
    }

    if (!args.filter_ifname.empty() && args.filter_ifindex != 0) {
        register_ifname(args.filter_netns_id, args.filter_ifindex, args.filter_ifname);
    }

    return 0;
}

int Output::print_header()
{
    spdlog::info("{:<10} {:<4} {:<7} {:<16} {:<18} {:<32} {}", "TIME(s)", "CPU", "PID", "COMM", "SKB", "FUNC", "TUPLE");
    return 0;
}

const char *Output::get_protocol_name(uint8_t protocol)
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

bool Output::protocol_has_ports(uint8_t protocol)
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

    if (Output::protocol_has_ports(tuple.l4_proto)) {
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

    if (Output::protocol_has_ports(tuple.l4_proto)) {
        return fmt::format("{}:{} -> {}:{} [{}]", s_ip, ntohs(tuple.sport), d_ip, ntohs(tuple.dport), proto_name);
    }
    return fmt::format("{} -> {} [{}]", s_ip, d_ip, proto_name);
}

std::string Output::format_tuple(const skb_tuple &tuple, const skb_meta &meta)
{
    if (tuple.l4_proto == 0) {
        return "-";
    }

    const char *proto_name = get_protocol_name(tuple.l4_proto);
    std::string tuple_str = (tuple.l3_proto == ETH_P_IPV6) ? format_ipv6_tuple(tuple, proto_name) : format_ipv4_tuple(tuple, proto_name);

    std::string dev_name = resolve_dev_name(meta.netns, meta.ifindex);
    if (!dev_name.empty()) {
        tuple_str += fmt::format(" dev:{}", dev_name);
    }

    return tuple_str;
}

std::string Output::format_tuple(const skb_event &event)
{
    return format_tuple(event.tuple, event.meta);
}

int Output::print_entry(const skb_event &event)
{
    if (start_ts == 0) {
        start_ts = event.ts;
    }
    double elapsed = (event.ts >= start_ts) ? (double)(event.ts - start_ts) / NS_PER_SEC : 0.0;

    SymdbMgr &symdb = SymdbMgr::getInstance();
    auto [ret_get_func_name, func_name] = symdb.get_func_by_addr(event.addr);
    if (func_name.empty()) {
        func_name = fmt::format("0x{:x}", event.addr);
    }

    std::string tuple_str = format_tuple(event);
    std::string comm = resolve_comm(event.pid);
    spdlog::info("{:<10.6f} {:<4} {:<7} {:<16} 0x{:<16x} {:<32} {}", elapsed, event.cpu_id, event.pid, comm, event.skb_addr, func_name, tuple_str);
    return 0;
}