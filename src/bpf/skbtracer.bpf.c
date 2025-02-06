// clang-format off
#include "vmlinux.h"
#include "skbtracer.h"
// clang-format on

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TRACK_SIZE 1024
#define RINGBUF_SIZE (256 * 1024)

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, bool);
    __uint(max_entries, MAX_TRACK_SIZE);
} skb_addresses SEC(".maps");

const static bool TRUE = true;
const volatile struct skb_config cfg;

static __always_inline u32 get_netns(struct sk_buff *skb)
{
    u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);
    if (netns == 0) {
        struct sock *sk = BPF_CORE_READ(skb, sk);
        if (sk != NULL) {
            netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
        }
    }
    return netns;
}

static __always_inline bool filter_meta(struct sk_buff *skb)
{
    if (cfg.netns && get_netns(skb) != cfg.netns) {
        return false;
    }
    if (cfg.mark && BPF_CORE_READ(skb, mark) != cfg.mark) {
        return false;
    }
    if (cfg.ifindex != 0 && BPF_CORE_READ(skb, dev, ifindex) != cfg.ifindex) {
        return false;
    }
    return true;
}

static __noinline bool filter_pcap_ebpf_l3(void *_skb, void *__skb, void *___skb, void *data, void *data_end)
{
    asm volatile("" : "+r"(data));
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool filter_pcap_l3(struct sk_buff *skb)
{
    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, network_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_ebpf_l3((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __noinline bool filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void *data_end)
{
    asm volatile("" : "+r"(data));
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
    u64 skb_addr = (u64)skb;
    if (cfg.track_skb && bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
        return true;
    }

    if (filter_pcap(skb) && filter_meta(skb)) {
        if (cfg.track_skb) {
            bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);
        }
        return true;
    }
    return false;
}

static __always_inline void set_output(void *ctx, struct sk_buff *skb, struct skb_event *event)
{
    event->ifindex = BPF_CORE_READ(skb, dev, ifindex);
    event->netns = get_netns(skb);
    event->pkt_type = BPF_CORE_READ_BITFIELD_PROBED(skb, pkt_type);
    event->ip_version = 0;
    event->protocol = 0;
    event->sport = 0;
    event->dport = 0;
    event->pad = 0;
    event->saddr.v6addr.d1 = 0;
    event->saddr.v6addr.d2 = 0;
    event->daddr.v6addr.d1 = 0;
    event->daddr.v6addr.d2 = 0;

    void *head = BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    void *ip_hdr_addr = head + network_header;

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_hdr_addr) < 0) {
        return;
    }

    if (ip.version == 4) {
        event->ip_version = 4;
        event->protocol = ip.protocol;
        event->saddr.v4addr = ip.saddr;
        event->daddr.v4addr = ip.daddr;

        if (event->protocol == IPPROTO_TCP || event->protocol == IPPROTO_UDP) {
            struct udphdr uh;
            void *trans_hdr = ip_hdr_addr + (ip.ihl * 4);
            if (bpf_probe_read_kernel(&uh, sizeof(uh), trans_hdr) == 0) {
                event->sport = __builtin_bswap16(uh.source);
                event->dport = __builtin_bswap16(uh.dest);
            }
        }
    } else if (ip.version == 6) {
        struct ipv6hdr ip6;
        if (bpf_probe_read_kernel(&ip6, sizeof(ip6), ip_hdr_addr) == 0) {
            event->ip_version = 6;
            event->protocol = ip6.nexthdr;
            __builtin_memcpy(&event->saddr.v6addr, &ip6.saddr, sizeof(event->saddr.v6addr));
            __builtin_memcpy(&event->daddr.v6addr, &ip6.daddr, sizeof(event->daddr.v6addr));

            if (event->protocol == IPPROTO_TCP || event->protocol == IPPROTO_UDP) {
                struct udphdr uh;
                void *trans_hdr = ip_hdr_addr + sizeof(struct ipv6hdr);
                if (bpf_probe_read_kernel(&uh, sizeof(uh), trans_hdr) == 0) {
                    event->sport = __builtin_bswap16(uh.source);
                    event->dport = __builtin_bswap16(uh.dest);
                }
            }
        }
    }
}

static __always_inline int kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
    if (!filter(skb)) {
        return false;
    }

    struct skb_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return BPF_OK;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ts = bpf_ktime_get_ns();
    event->cpu_id = bpf_get_smp_processor_id();
    event->skb_addr = (u64)skb;
    event->addr = bpf_get_func_ip(ctx);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    set_output(ctx, skb, event);

    bpf_ringbuf_submit(event, 0);
    return BPF_OK;
}

#define SKBTRACER_ADD_KPROBE(X)                                                                                                                                                    \
    SEC("skbtracer/skb-" #X)                                                                                                                                                       \
    int kprobe_skb_##X(struct pt_regs *ctx)                                                                                                                                        \
    {                                                                                                                                                                              \
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##X(ctx);                                                                                                              \
        return kprobe_skb(skb, ctx);                                                                                                                                               \
    }

SKBTRACER_ADD_KPROBE(1)
SKBTRACER_ADD_KPROBE(2)
SKBTRACER_ADD_KPROBE(3)
SKBTRACER_ADD_KPROBE(4)
SKBTRACER_ADD_KPROBE(5)

SEC("kprobe/__kfree_skb")
int BPF_KPROBE(trace_kfree_skb)
{
    u64 skb_addr = (u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&skb_addresses, &skb_addr);
    return BPF_OK;
}

SEC("kprobe/consume_skb")
int BPF_KPROBE(trace_consume_skb)
{
    u64 skb_addr = (u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&skb_addresses, &skb_addr);
    return BPF_OK;
}

static __always_inline int track_skb_clone(struct sk_buff *old, struct sk_buff *new)
{
    if (!cfg.track_skb || !old || !new) {
        return BPF_OK;
    }

    u64 skb_addr_old = (u64)old;
    u64 skb_addr_new = (u64)new;
    if (bpf_map_lookup_elem(&skb_addresses, &skb_addr_old)) {
        bpf_map_update_elem(&skb_addresses, &skb_addr_new, &TRUE, BPF_ANY);
    }
    return BPF_OK;
}

SEC("fexit/skb_clone")
int BPF_PROG(trace_skb_clone_exit, struct sk_buff *old, gfp_t gfp_mask, struct sk_buff *new)
{
    return track_skb_clone(old, new);
}

SEC("fexit/skb_copy")
int BPF_PROG(trace_skb_copy_exit, struct sk_buff *old, gfp_t gfp_mask, struct sk_buff *new)
{
    return track_skb_clone(old, new);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";