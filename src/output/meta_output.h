#ifndef __META_OUTPUT_H__
#define __META_OUTPUT_H__

#include <string>

extern "C" {
#include <linux/types.h>
#include "skbtracer.h"
}

class MetaOutput {
  public:
    static std::string format_header();
    static std::string format_meta(const skb_meta &meta);
    static std::string format_meta(const skb_event &event);
};

#endif // __META_OUTPUT_H__
