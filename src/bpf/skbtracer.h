#ifndef __SKBTRACER_H__
#define __SKBTRACER_H__

struct event_t {
	__u32 pid;
	__u32 type;
	__u64 addr;
	__u64 skb_addr;
	__u64 ts;
	__u64 print_skb_id;
	__s64 print_stack_id;
	__u32 cpu_id;
} __attribute__((packed));

#endif /* __SKBTRACER_H__ */