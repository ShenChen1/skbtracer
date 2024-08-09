#ifndef __BPF_COMMON_H__
#define __BPF_COMMON_H__

namespace libbpf {
extern "C" {
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/filter.h>
}
} /* namespace libbpf */

namespace bpfhelper {
extern "C" {
#include "trace_helpers.h"
}
} /* namespace bpfhelper */

#endif //__BPF_COMMON_H__