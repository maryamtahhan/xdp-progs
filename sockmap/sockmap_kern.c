/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h> /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sock_map_rx SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog2(struct __sk_buff *skb)
{
	__u32 lport = skb->local_port;
	__u32 idx = 0;

	if (lport == 10000)
		return bpf_sk_redirect_map(skb, &sock_map_rx, idx, 0);

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
