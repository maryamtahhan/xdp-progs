/* SPDX-License-Identifier: GPL-2.0 */
#include "sockmap.h"

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
	__u32 lport = skb->local_port;
	__u32 idx = 0;

	if (lport == 10000)
		return bpf_sk_redirect_map(skb, &sock_map_rx, idx, 0);

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
