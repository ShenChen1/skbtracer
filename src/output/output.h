#ifndef __OUTPUT_H__
#define __OUTPUT_H__


#include "options.h"

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

private:
    bool output_meta;
    bool output_tuple;
};

#endif //__OUTPUT_H__