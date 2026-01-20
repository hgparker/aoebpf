// go: build ignore

#define __TARGET_ARG_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int epoll_work(struct trace_event_raw_sys_enter *ctx) {
  bpf_printk("Hello from epoll\n");
  return 0;
}
