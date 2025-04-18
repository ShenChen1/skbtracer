#include "meta_output.h"
#include "dev_cache.h"

#include <arpa/inet.h>
#include <spdlog/fmt/fmt.h>

std::string MetaOutput::format_header()
{
    return fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} {:<8}",
                       "NETNS", "IFACE", "MTU", "LEN", "PROTO", "MARK");
}

std::string MetaOutput::format_meta(const skb_meta &meta)
{
    std::string iface_str = DevCache::format_iface(meta.netns, meta.ifindex);
    std::string proto_str = fmt::format("0x{:04x}", ntohs(meta.proto));

    return fmt::format("{:<11} {:<12} {:<6} {:<7} {:<8} 0x{:<6x}",
                       meta.netns, iface_str, meta.mtu, meta.len, proto_str, meta.mark);
}

std::string MetaOutput::format_meta(const skb_event &event)
{
    return format_meta(event.meta);
}
