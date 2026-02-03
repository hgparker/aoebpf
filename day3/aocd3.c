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

// Helper variable to get powers of 10
static const __u64 powers10[19] = {
  1,
  10,
  100,
  1000,
  10000,
  100000,
  1000000,
  10000000,
  100000000,
  1000000000,
  10000000000,
  100000000000,
  1000000000000,
  10000000000000,
  100000000000000,
  1000000000000000,
  10000000000000000,
  100000000000000000,
  1000000000000000000,
};

// Auxiliary structure we'll need for the maps

struct InputWorkspace {
  __u32 locked; // ebpf programs will use CAS on this
  __u32 input[MAX_INPUT_LEN]; // actual input lives here
  __u32 input_len;
  __s32 next_k; // which char in input we should use next to enrich best_suffix[]
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
  /* bpf_printk("Hello from epoll with SEQUENCE_LEN value %d", sl); */

  struct InputWorkspace *inputWorkspace = NULL;
  __u32 inputIndex;
  #pragma unroll
  for (__u32 i=0; i < BATCH_SIZE; i++) {
    // The real loop condition
    __u32 adjustedIndex = i + first_workable_input_index;
    if (adjustedIndex >= first_unworkable_input_index)
      return 0;
    if (adjustedIndex >= MAX_NUM_INPUTS) {
      bpf_printk("Something has gone wrong -- this should not have happened!");
      return 0;
    }
    // Get map at adjusted index
    struct InputWorkspace *candidateInputWorkspace = bpf_map_lookup_elem(&input_workspaces, &adjustedIndex);
    // Obligatory pointer check
    if (!candidateInputWorkspace) {
      bpf_printk("Failed map lookup!");
      return 0;
    }
    // Try to get lock
    if (__sync_val_compare_and_swap(&candidateInputWorkspace->locked, 0, 1) != 0)
      continue;
    // If we have lock, break and do business logic
    inputIndex = adjustedIndex;
    inputWorkspace = candidateInputWorkspace;
    /* bpf_printk("Obtained lock for inputIndex %d\n", inputIndex); */
    break;
  }
  
  // "Business logic" -> i.e, do one DP pass
  // Obligatory pointer check before pulling out next_k
  if (!inputWorkspace) {
    bpf_printk("Logic error, this should not have happened");
    return 0;
  }
  __u32 nextK = inputWorkspace->next_k;
  /* bpf_printk("inputIndex = %d, nextK = %d\n", inputIndex, nextK); */

  // If done, try to push workable index
  if (nextK == -1) {
    if (first_workable_input_index == inputIndex) {
      first_workable_input_index += 1; // safe because only this execution would meet condition to increment
      /* bpf_printk("All done with inputIndex = %d\n", inputIndex); */
    }
    return 0; // don't need to unlock b/c never will be considered again
  }

  // Pull out the digit we'll use for the dp
  if (nextK < 0 || nextK >= MAX_INPUT_LEN)
    return 0;
  __u32 digit = inputWorkspace->input[nextK];

  // The DP pass
  #pragma unroll
  for (__u32 t=SEQUENCE_LEN-1; t>=1; t--) {
    if (inputWorkspace->best_suffix[t-1] != -1) {
      __s64 cand = (powers10[t] * digit) + inputWorkspace->best_suffix[t-1];
      if (cand > inputWorkspace->best_suffix[t]) 
        inputWorkspace->best_suffix[t] = cand;
     }
  }
  
  // Adjust next_k downward
  inputWorkspace->next_k -= 1;
  
  // Release the lock in an overkill way to prevent CPU/compiler instruction reordering
  __sync_lock_test_and_set(&inputWorkspace->locked, 0);
  
  return 0;
}
