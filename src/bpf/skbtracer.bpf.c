// clang-format off
#include "vmlinux.h"
#include "skbtracer.h"
// clang-format on

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (256 * 1024)

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

const volatile struct skb_config cfg;

static __always_inline bool is_vlan_proto(__be16 proto)
{
    return proto == bpf_htons(ETH_P_8021Q) ||
           proto == bpf_htons(ETH_P_8021AD);
}

/* Locate true L3 header offset by skipping 802.1Q / 802.1ad VLAN tags (up to 2 layers for QinQ) */
static __always_inline u16 get_l3_header_offset(struct sk_buff *skb, void *head)
{
    u16 l3_off = BPF_CORE_READ(skb, network_header);
    __be16 proto = BPF_CORE_READ(skb, protocol);

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (!is_vlan_proto(proto)) {
            break;
        }

        struct vlan_hdr *vhdr = head + l3_off;
        proto = BPF_CORE_READ(vhdr, h_vlan_encapsulated_proto);
        l3_off += sizeof(struct vlan_hdr);
    }

    return l3_off;
}

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
    return filter_pcap(skb) && filter_meta(skb);
}

static __always_inline void set_meta(struct sk_buff *skb, struct skb_meta *meta)
{
    meta->netns = get_netns(skb);
    meta->mark = BPF_CORE_READ(skb, mark);
    meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
    meta->len = BPF_CORE_READ(skb, len);
    meta->mtu = BPF_CORE_READ(skb, dev, mtu);
    meta->proto = BPF_CORE_READ(skb, protocol);
}

static __always_inline void __set_tuple(struct skb_tuple *tuple, void *head, u16 l3_off, bool is_ipv4)
{
    void *ip_hdr_addr = head + l3_off;
    void *trans_hdr;

    if (is_ipv4) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_hdr_addr) < 0) {
            return;
        }

        tuple->l3_proto = ETH_P_IP;
        tuple->l4_proto = ip.protocol;
        tuple->saddr.v4addr = ip.saddr;
        tuple->daddr.v4addr = ip.daddr;
        trans_hdr = ip_hdr_addr + (ip.ihl * 4);
    } else {
        struct ipv6hdr ip6;
        if (bpf_probe_read_kernel(&ip6, sizeof(ip6), ip_hdr_addr) < 0) {
            return;
        }

        tuple->l3_proto = ETH_P_IPV6;
        tuple->l4_proto = ip6.nexthdr;
        __builtin_memcpy(&tuple->saddr.v6addr, &ip6.saddr, sizeof(tuple->saddr.v6addr));
        __builtin_memcpy(&tuple->daddr.v6addr, &ip6.daddr, sizeof(tuple->daddr.v6addr));
        trans_hdr = ip_hdr_addr + sizeof(struct ipv6hdr);
    }

    if (tuple->l4_proto == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), trans_hdr) == 0) {
            tuple->sport = tcp.source;
            tuple->dport = tcp.dest;
            tuple->tcp_flags = ((const __u8 *)&tcp)[13];
        }
    } else if (tuple->l4_proto == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), trans_hdr) == 0) {
            tuple->sport = udp.source;
            tuple->dport = udp.dest;
        }
    }
}

static __always_inline void set_tuple(struct sk_buff *skb, struct skb_tuple *tuple)
{
    tuple->l3_proto = 0;
    tuple->l4_proto = 0;
    tuple->tcp_flags = 0;
    tuple->sport = 0;
    tuple->dport = 0;
    tuple->saddr.v6addr.d1 = 0;
    tuple->saddr.v6addr.d2 = 0;
    tuple->daddr.v6addr.d1 = 0;
    tuple->daddr.v6addr.d2 = 0;

    void *head = BPF_CORE_READ(skb, head);
    u16 l3_off = get_l3_header_offset(skb, head);
    void *ip_hdr_addr = head + l3_off;

    struct iphdr l3_hdr;
    if (bpf_probe_read_kernel(&l3_hdr, sizeof(l3_hdr), ip_hdr_addr) < 0) {
        return;
    }

    if (l3_hdr.version != 4 && l3_hdr.version != 6) {
        return;
    }

    __set_tuple(tuple, head, l3_off, l3_hdr.version == 4);
}

static __always_inline void set_output(void *ctx, struct sk_buff *skb, struct skb_event *event)
{
    set_meta(skb, &event->meta);
    set_tuple(skb, &event->tuple);
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
    event->cpu_id = bpf_get_smp_processor_id();
    event->ts = bpf_ktime_get_ns();
    event->skb_addr = (u64)skb;
    event->addr = bpf_get_func_ip(ctx);

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

char LICENSE[] SEC("license") = "Dual BSD/GPL";