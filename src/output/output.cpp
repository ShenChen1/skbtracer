#include "output.h"
#include "dev_cache.h"
#include "meta_output.h"
#include "symdb.h"
#include "time_output.h"
#include "tuple_output.h"

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>

constexpr double NS_PER_SEC = 1e9;

Output::Output()
{
}

Output::~Output()
{
}

int Output::init(const Options::args &args)
{
    spdlog::set_pattern("%v");
    output_meta = args.output_meta;
    output_tuple = args.output_tuple;
    start_ts = 0;

    bool ok = false;
    timestamp_mode = TimeOutput::parse_mode(args.timestamp, ok);
    if (!ok) {
        timestamp_mode = TimestampMode::NONE;
    }

    struct stat st{};
    if (stat("/proc/self/ns/net", &st) == 0) {
        DevCache::set_current_netns_id(static_cast<uint32_t>(st.st_ino));
    }

    if (!args.filter_ifname.empty() && args.filter_ifindex != 0) {
        DevCache::register_ifname(args.filter_netns_id, args.filter_ifindex, args.filter_ifname);
    }

    return 0;
}

int Output::print_header()
{
    std::string common_base = fmt::format("{:<4} {:<20} {:<18} {:<32}",
                                          "CPU", "PROCESS", "SKB", "FUNC");
    std::string base;
    if (timestamp_mode != TimestampMode::NONE) {
        base = fmt::format("{} {}", TimeOutput::format_header(timestamp_mode), common_base);
    } else {
        base = common_base;
    }

    if (output_meta && output_tuple) {
        spdlog::info("{} {} {}", base, MetaOutput::format_header(), "TUPLE");
    } else if (output_meta) {
        spdlog::info("{} {}", base, MetaOutput::format_header());
    } else if (output_tuple) {
        spdlog::info("{} {}", base, "TUPLE");
    } else {
        spdlog::info("{}", base);
    }
    return 0;
}

int Output::print_entry(const skb_event &event)
{
    if (start_ts == 0) {
        start_ts = event.ts;
    }
    SymdbMgr &symdb = SymdbMgr::getInstance();
    auto [ret_get_func_name, func_name] = symdb.get_func_by_addr(event.addr);
    if (func_name.empty()) {
        func_name = fmt::format("0x{:x}", event.addr);
    }

    std::string proc = DevCache::format_proc(event.pid);
    std::string common_base = fmt::format("{:<4} {:<20} 0x{:<16x} {:<32}",
                                          event.cpu_id, proc, event.skb_addr, func_name);
    std::string base;
    if (timestamp_mode != TimestampMode::NONE) {
        std::string ts_str = TimeOutput::format_time(timestamp_mode, event.ts, start_ts);
        base = fmt::format("{} {}", ts_str, common_base);
    } else {
        base = common_base;
    }

    if (output_meta && output_tuple) {
        std::string meta_str = MetaOutput::format_meta(event.meta);
        std::string tuple_str = TupleOutput::format_tuple(event.tuple);
        spdlog::info("{} {} {}", base, meta_str, tuple_str);
    } else if (output_meta) {
        std::string meta_str = MetaOutput::format_meta(event.meta);
        spdlog::info("{} {}", base, meta_str);
    } else if (output_tuple) {
        std::string tuple_str = TupleOutput::format_tuple(event.tuple);
        spdlog::info("{} {}", base, tuple_str);
    } else {
        spdlog::info("{}", base);
    }
    return 0;
}