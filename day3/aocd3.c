//go: build ignore

#define __TARGET_ARG_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

// Some preprocessor directives

#define MAX_INPUT_LEN 500
#define MAX_NUM_INPUTS 500
#ifndef SEQUENCE_LEN
  #define SEQUENCE_LEN 2
#endif

// Auxiliary structures we'll need for the maps

struct InputWorkspace {
  __u8 locked; // ebpf programs will use CAS on this
  char input[MAX_INPUT_LEN]; // actual input lives here
  __u32 next_k; // which char in input we should use next to enrich best_suffix[]
  __u32 best_suffix[SEQUENCE_LEN + 1]; // best_suffix[t] stores best suffix of length t
};

struct WorkState {
  __u32 first_unworked_input; // Monotonically increases
  __u32 workable_input_boundary; // Every actually workable input has index strictly less than
};

// eBPF maps for accessing input and saving state

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_NUM_INPUTS);
  __type(key, __u32);
  __type(value, struct InputWorkspace);
} input_workspaces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct WorkState);
} work_state SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int epoll_work(struct trace_event_raw_sys_enter *ctx) {
  __u32 sl = SEQUENCE_LEN;
  bpf_printk("Hello from epoll with SEQUENCE_LEN value", sl);
  return 0;
}
