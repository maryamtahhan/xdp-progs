/* SPDX-License-Identifier: GPL-2.0 */
#include "sockmap.h"

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
	return skb->len;
}

char _license[] SEC("license") = "GPL";
