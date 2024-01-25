#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline int
kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
    bpf_printk("skb %llx, func = %llx", skb, PT_REGS_IP(ctx));
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";