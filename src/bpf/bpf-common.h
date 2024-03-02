#ifndef __BPF_COMMON_H__
#define __BPF_COMMON_H__

namespace bpfhelper {
extern "C" {
#include "trace_helpers.h"
}
} /* namespace bpfhelper */

namespace libbpf {
extern "C" {
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
}
} /* namespace libbpf */

#endif //__BPF_COMMON_H__