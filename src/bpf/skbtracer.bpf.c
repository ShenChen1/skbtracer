#include "vmlinux.h"
#include "skbtracer.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TRACK_SIZE 1024
#define MAX_QUEUE_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct event_t);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, bool);
	__uint(max_entries, MAX_TRACK_SIZE);
} skb_addresses SEC(".maps");

const static bool TRUE = true;

static __always_inline int
kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
	struct event_t event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.ts = bpf_ktime_get_ns();
	event.cpu_id = bpf_get_smp_processor_id();

	event.skb_addr = (u64)skb;
	event.addr = bpf_get_func_ip(ctx);
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}

#define SKBTRACER_ADD_KPROBE(X)                                       \
    SEC("kprobe/skb-" #X)                                             \
    int kprobe_skb_##X(struct pt_regs *ctx)                           \
    {                                                                 \
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##X(ctx); \
        return kprobe_skb(skb, ctx);                                  \
    }

SKBTRACER_ADD_KPROBE(1)
SKBTRACER_ADD_KPROBE(2)
SKBTRACER_ADD_KPROBE(3)
SKBTRACER_ADD_KPROBE(4)
SKBTRACER_ADD_KPROBE(5)

SEC("kprobe/kfree_skbmem")
int BPF_KPROBE(kfree_skbmem)
{
	u64 skb_addr = (u64)PT_REGS_PARM1(ctx);
	bpf_map_delete_elem(&skb_addresses, &skb_addr);
	return BPF_OK;
}

static __always_inline int
track_skb_clone(u64 old, u64 new)
{
	if (bpf_map_lookup_elem(&skb_addresses, &old))
		bpf_map_update_elem(&skb_addresses, &new, &TRUE, BPF_ANY);
	return BPF_OK;
}

SEC("kprobe/skb_clone")
int BPF_KRETPROBE(skb_clone)
{
	u64 old = (u64)PT_REGS_PARM1(ctx);
	u64 new = (u64)PT_REGS_RC(ctx);
	return track_skb_clone(old, new);
}

SEC("kprobe/skb_copy")
int BPF_KRETPROBE(skb_copy) {
	u64 old = (u64)PT_REGS_PARM1(ctx);
	u64 new = (u64)PT_REGS_RET(ctx);
	return track_skb_clone(old, new);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";