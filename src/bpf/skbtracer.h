#ifndef __SKBTRACER_H__
#define __SKBTRACER_H__

union addr {
    __u32 v4addr;
    struct {
        __u64 d1;
        __u64 d2;
    } v6addr;
} __attribute__((packed));

struct skb_event {
    __u64 ts;
    __u64 skb_addr;
    __u64 addr;
    __u32 pid;
    __u32 cpu_id;
    union addr saddr;
    union addr daddr;
    __u16 sport;
    __u16 dport;
    __u8 ip_version;
    __u8 protocol;
    __u8 pkt_type;
    __u8 pad;
    __u32 ifindex;
    __u32 netns;
    char comm[16];
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
    __u8 track_skb;
} __attribute__((packed));

#endif /* __SKBTRACER_H__ */