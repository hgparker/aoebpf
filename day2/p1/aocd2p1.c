
// go:build ignore

#define __TARGET_ARCH_x86

#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include <linux/ptrace.h>
#include <linux/pkt_cls.h>

char __license[] SEC("license") = "GPL";

// eBPF map we use to record results
// Per CPU allows us to sidestep concurrency worries

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u32);
} state SEC(".maps");

// The main eBPF function

SEC("tc")
int handle_egress(struct __sk_buff *skb) {
  return TC_ACT_OK;
}

