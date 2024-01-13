#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/skb/kfree_skb")
int tracepoint_kmem_cache_alloc_node(void *__args)
{
	struct trace_event_raw_kfree_skb *arg = __args;
	bpf_printk("kfree_skb: skb=%p, reason=%d\n", arg->skbaddr, arg->reason);
	return 0;
}