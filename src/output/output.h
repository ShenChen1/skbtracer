#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "dev_cache.h"
#include "meta_output.h"
#include "options.h"
#include "time_output.h"
#include "tuple_output.h"

#include <cstdint>
#include <string>

extern "C" {
#include <linux/types.h>
#include "skbtracer.h"
}

class Output {
  public:
    Output();
    ~Output();

    int init(const Options::args &args);
    int print_header();
    int print_entry(const skb_event &event);

    static const char *get_protocol_name(uint8_t protocol) {
        return TupleOutput::get_protocol_name(protocol);
    }
    static bool protocol_has_ports(uint8_t protocol) {
        return TupleOutput::protocol_has_ports(protocol);
    }
    static std::string format_tuple(const skb_tuple &tuple) {
        return TupleOutput::format_tuple(tuple);
    }
    static std::string format_tuple(const skb_tuple &tuple, const skb_meta &meta) {
        return TupleOutput::format_tuple(tuple, meta);
    }
    static std::string format_tuple(const skb_event &event) {
        return TupleOutput::format_tuple(event);
    }

    static std::string format_meta_header() {
        return MetaOutput::format_header();
    }
    static std::string format_meta(const skb_meta &meta) {
        return MetaOutput::format_meta(meta);
    }
    static std::string format_meta(const skb_event &event) {
        return MetaOutput::format_meta(event);
    }

    static std::string format_proc(uint32_t pid) {
        return DevCache::format_proc(pid);
    }

    static void register_ifname(uint32_t netns, uint32_t ifindex, const std::string &ifname) {
        DevCache::register_ifname(netns, ifindex, ifname);
    }
    static std::string resolve_dev_name(uint32_t netns, uint32_t ifindex) {
        return DevCache::resolve_dev_name(netns, ifindex);
    }
    static std::string format_iface(uint32_t netns, uint32_t ifindex) {
        return DevCache::format_iface(netns, ifindex);
    }
    static void clear_ifname_cache() {
        DevCache::clear_ifname_cache();
    }

    TimestampMode get_timestamp_mode() const {
        return timestamp_mode;
    }

  private:
    bool output_meta = false;
    bool output_tuple = false;
    TimestampMode timestamp_mode = TimestampMode::NONE;
    uint64_t start_ts = 0;
};

#endif // __OUTPUT_H__