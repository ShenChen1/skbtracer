#ifndef __OUTPUT_H__
#define __OUTPUT_H__


#include "options.h"
#include <cstdint>

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

    static const char *get_protocol_name(uint8_t protocol);
    static bool protocol_has_ports(uint8_t protocol);
    static std::string format_tuple(const skb_event &event);

    static void register_ifname(uint32_t netns, uint32_t ifindex, const std::string &ifname);
    static std::string resolve_dev_name(uint32_t netns, uint32_t ifindex);
    static void clear_ifname_cache();

private:
    bool output_meta = false;
    bool output_tuple = false;
    uint64_t start_ts = 0;
};
#endif //__OUTPUT_H__