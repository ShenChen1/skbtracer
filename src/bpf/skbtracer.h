#ifndef __SKBTRACER_H__
#define __SKBTRACER_H__

union addr {
    __u32 v4addr;
    struct {
        __u64 d1;
        __u64 d2;
    } v6addr;
} __attribute__((packed));

struct skb_meta {
    __u32 netns;
    __u32 mark;
    __u32 ifindex;
    __u32 len;
    __u32 mtu;
} __attribute__((packed));

struct skb_tuple {
    union addr saddr;
    union addr daddr;
    __u16 sport;
    __u16 dport;
    __u16 l3_proto;
    __u8 l4_proto;
    __u8 tcp_flags;
} __attribute__((packed));

struct skb_event {
    __u32 pid;
    __u32 cpu_id;
    __u64 ts;
    __u64 skb_addr;
    __u64 addr;
    struct skb_meta meta;
    struct skb_tuple tuple;
} __attribute__((packed));

struct skb_config {
    __u32 netns;
    __u32 mark;
    __u32 ifindex;
    __u8 output_meta;
    __u8 output_tuple;
    __u8 output_skb;
    __u8 output_stack;
    __u8 is_set;
} __attribute__((packed));

#endif /* __SKBTRACER_H__ */