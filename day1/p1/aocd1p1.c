
//go:build ignore

#define __TARGET_ARCH_x86

#include "linux/bpf.h"
#include "linux/types.h"
#include <linux/ptrace.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

// Next two structs are basically from bash

struct word_desc {
    char *word;
    int flags;
};

struct word_list {
    struct word_list *next;
    struct word_desc *word;
};

// eBPF map we use to record state
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} state SEC(".maps");

// Helper for parsing
static int extract_integer_part(char *s) {
	int res = 0;
	#pragma unroll
	for (int i=1; i<10; i++) {
		if (s[i] < '0' ||s[i] > '9')
			break;
		res = res*10 +(s[i]-'0');
	}
	return res;
}

// Helper for doing % 100 operation on signed 32 bit integers :)
__u32 mod100(__s32 curr) {
	if (curr > 0) {
		return ((__u32) curr) % 100;
	}
	else if (curr < 0) {
		__u32 add_inv_curr = (__u32)(-curr);
		__u32 add_inv_curr_res = add_inv_curr % 100;
		if (add_inv_curr_res == 0)
			return 0;
		else
			return 100-add_inv_curr_res;
	} else
		return 0;
}

SEC("uprobe//bin/bash:echo_builtin")
int BPF_UPROBE(trace_echo_entry, struct word_list *list) {

    // Get first word passed to echo and put it in first_word
    char first_word[64];
    void *word_desc_ptr;
    char *word_ptr;
    bpf_probe_read_user(&word_desc_ptr, sizeof(word_desc_ptr), &list->word);
    bpf_probe_read_user(&word_ptr, sizeof(word_ptr), word_desc_ptr);
    long first_word_len = bpf_probe_read_user_str(&first_word, sizeof(first_word), word_ptr);

    if (first_word_len>0) {
	// Get val from extracted integer part
	int val = extract_integer_part(first_word);
	if (first_word[0] == 'L')
		val *= -1;
	bpf_printk("val: %d\n", val);

	// Get pointers to curr and ans
	__u32 curr_index = 0;
	__u32 ans_index = 1;
	__s32 *curr_ptr = bpf_map_lookup_elem(&state, &curr_index);
	__s32 *ans_ptr = bpf_map_lookup_elem(&state, &ans_index);

	// Do the thing
	if (curr_ptr && ans_ptr) {
		*curr_ptr += val;
		*curr_ptr = mod100(*curr_ptr);
		if (*curr_ptr == 0)
			*ans_ptr += 1;
	}
    }
    return 0;
}

char __license[] SEC("license") = "GPL";

