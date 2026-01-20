// go: build ignore

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

// Auxiliary structure we'll need for the map

struct InputWorkspace {
  __u8 locked;
  char input[MAX_INPUT_LEN];
  __u32 next_k;
  __u32 best_suffix[SEQUENCE_LEN];
};

struct Workspace {
  __u32 first_workable_input;
  __u32 last_workable_input;
  struct InputWorkspace input_workspaces[MAX_NUM_INPUTS];
};

// eBPF map for accessing input and saving state

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct Workspace);
} workspace SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int epoll_work(struct trace_event_raw_sys_enter *ctx) {
  bpf_printk("Hello from epoll\n");
  return 0;
}
