#include "vmlinux.h"
#include "skbtracer.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TRACK_SIZE 1024
#define MAX_QUEUE_ENTRIES 10000

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct skb_event);
    __uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, bool);
    __uint(max_entries, MAX_TRACK_SIZE);
} skb_addresses SEC(".maps");

const static bool TRUE = true;
const static volatile struct skb_config cfg;

static __always_inline bool filter_meta(struct sk_buff *skb)
{
/*  if (cfg.netns && get_netns(skb) != cfg.netns) {
        return false;
    }
    if (cfg.mark && BPF_CORE_READ(skb, mark) != cfg.mark) {
        return false;
    }
    if (cfg.ifindex != 0 && BPF_CORE_READ(skb, dev, ifindex) != cfg.ifindex) {
        return false;
    } */
    return true;
}

SEC("pcap_ebpf_l3")
bool filter_pcap_ebpf_l3(void *_skb, void *__skb, void *___skb, void *data, void *data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool filter_pcap_l3(struct sk_buff *skb)
{
    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, network_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_ebpf_l3((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

SEC("pcap_ebpf_l2")
bool filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void *data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool filter_pcap_l2(struct sk_buff *skb)
{
    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, mac_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool filter_pcap(struct sk_buff *skb)
{
    if (BPF_CORE_READ(skb, mac_len) == 0)
        return filter_pcap_l3(skb);
    return filter_pcap_l2(skb);
}

static __always_inline bool filter(struct sk_buff *skb)
{
    return filter_pcap(skb) && filter_meta(skb);
}

static __always_inline void set_output(void *ctx, struct sk_buff *skb, struct skb_event *event)
{
    if (cfg.output_meta) {
        // set_meta(skb, &event->meta);
    }

    if (cfg.output_tuple) {
        // set_tuple(skb, &event->tuple);
    }

    if (cfg.output_skb) {
        // set_skb_btf(skb, &event->print_skb_id);
    }
}

static __always_inline int kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
    struct skb_event event = {};

    if (!filter(skb)) {
        return false;
    }
    set_output(ctx, skb, &event);

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

static __always_inline int track_skb_clone(u64 old, u64 new)
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
int BPF_KRETPROBE(skb_copy)
{
    u64 old = (u64)PT_REGS_PARM1(ctx);
    u64 new = (u64)PT_REGS_RET(ctx);
    return track_skb_clone(old, new);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";