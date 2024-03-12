#ifndef __SKBTRACER_H__
#define __SKBTRACER_H__

struct skb_event {
    __u32 pid;
    __u32 type;
    __u64 addr;
    __u64 skb_addr;
    __u64 ts;
    __u64 print_skb_id;
    __s64 print_stack_id;
    __u32 cpu_id;
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