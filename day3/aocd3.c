//go: build ignore

#define __TARGET_ARG_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

// Some preprocessor directives

#define BATCH_SIZE 10
#define MAX_INPUT_LEN 500
#define MAX_NUM_INPUTS 500
#ifndef SEQUENCE_LEN
  #define SEQUENCE_LEN 2
#endif

// Auxiliary structure we'll need for the maps

struct InputWorkspace {
  __u32 locked; // ebpf programs will use CAS on this
  char input[MAX_INPUT_LEN]; // actual input lives here
  __u32 next_k; // which char in input we should use next to enrich best_suffix[]
  __s64 best_suffix[SEQUENCE_LEN + 1]; // best_suffix[t] stores best suffix of length t
};

// eBPF maps for accessing input and saving state

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_NUM_INPUTS);
  __type(key, __u32);
  __type(value, struct InputWorkspace);
} input_workspaces SEC(".maps");

// Global variables that also function as maps

__u32 first_workable_input_index; // Monotonically increases
__u32 first_unworkable_input_index; // Nothing >= is workable

// Actual program
SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int epoll_work(struct trace_event_raw_sys_enter *ctx) {
  __u32 sl = SEQUENCE_LEN;
  bpf_printk("Hello from epoll with SEQUENCE_LEN value %d", sl);
  #pragma unroll
  for (__u32 i=0; i < BATCH_SIZE; i++) {
    // The real loop condition
    __u32 adjustedIndex = i + first_workable_input_index;
    if (adjustedIndex >= first_unworkable_input_index || adjustedIndex >= MAX_NUM_INPUTS)
      break;
    // Get map at adjusted index
    struct InputWorkspace *inputWorkspace;
    inputWorkspace = bpf_map_lookup_elem(&input_workspaces, &adjustedIndex);
    // Obligatory pointer check
    if (!inputWorkspace)
      break;
    // Try to get lock
    if (__sync_val_compare_and_swap(&inputWorkspace->locked, 0, 1) != 0)
      continue;

    // Release the lock in an overkill way to prevent CPU/compiler instruction reordering
    __sync_lock_test_and_set(&inputWorkspace->locked, 0);
  }
  return 0;
}
