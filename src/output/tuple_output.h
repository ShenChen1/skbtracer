#ifndef __TUPLE_OUTPUT_H__
#define __TUPLE_OUTPUT_H__

#include <cstdint>
#include <string>

extern "C" {
#include <linux/types.h>
#include "skbtracer.h"
}

class TupleOutput {
  public:
    static const char *get_protocol_name(uint8_t protocol);
    static bool protocol_has_ports(uint8_t protocol);
    static std::string format_tuple(const skb_tuple &tuple);
    static std::string format_tuple(const skb_tuple &tuple, const skb_meta &meta);
    static std::string format_tuple(const skb_event &event);
};

#endif // __TUPLE_OUTPUT_H__
