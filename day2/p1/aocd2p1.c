// go:build ignore

#define __TARGET_ARCH_x86

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

// eBPF map we use to record results
// Per CPU allows us to sidestep concurrency worries

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} state SEC(".maps");

// Helper arithmetic functions
int get_base10_len(__u32 number) {
  int power10 = 1;
  for (int k=0; k < 20; k++) {
    if (number < power10)
      power10 *= 10;
    else
      return k;
  }
  return 20;
}

int bad(__u32 number) {
  int number_len = get_base10_len(number);
  if (number_len % 2 != 0)
    return 0;
  int useful_power10 = 1;
  for (int k = 0; k <= number_len/2; k++)
    useful_power10 *= 10;
  if (number / useful_power10 == number % useful_power10)
    return 1;
  return 0;
}

// The main eBPF function

SEC("tc")
int handle_egress(struct __sk_buff *skb) {

  // Get start and end pointers
  void *data = (void *)(long) skb->data;
  void *data_end = (void *)(long) skb->data_end;
  
  // Get L3 protocol id from ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
  __be16 l3_protocol_id = eth->h_proto;

  // If not IPv4, give up
  if (l3_protocol_id != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // Get L4 protocol id from ip header
  struct  iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip+1) > data_end)
    return TC_ACT_OK;
  __u8 l4_protocol_id = ip->protocol;

  // If not TCP, give up
  if (l4_protocol_id != IPPROTO_TCP)
    return TC_ACT_OK;

  // Get port number from TCP header
  struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
  if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;
  __be16 dest_port = tcp->dest;

  // If not to port 9999, give up
  if (bpf_ntohs(dest_port) != 9999)
    return TC_ACT_OK;  

  // Get sequence number and little-endianize it
  __u32 sequence_number = bpf_ntohs(tcp->seq);
 
  bpf_printk("Eligible input on CPU %d had sequence number: %d\n", bpf_get_smp_processor_id(), sequence_number);

  // If sequence number meets criterion, add to per-cpu map
  if (bad(sequence_number) == 1) {
    __u32 key = 0;
    __u32 *sum = bpf_map_lookup_elem(&state, &key);
    *sum += sequence_number;
  }

  // Drop this packet, though
  return TC_ACT_SHOT;
}
