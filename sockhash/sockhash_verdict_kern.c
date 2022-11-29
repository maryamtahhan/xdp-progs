/* SPDX-License-Identifier: GPL-2.0 */
#include "sockhash.h"

static inline
void extract_socket_key(struct __sk_buff *skb, struct socket_key *key)
{
	key->src_ip = skb->remote_ip4;
	key->dst_ip = skb->local_ip4;
	key->src_port = skb->remote_port >> 16;
	key->dst_port = (bpf_htonl(skb->local_port)) >> 16;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
	struct socket_key key;

	extract_socket_key(skb, &key);

	return bpf_sk_redirect_hash(skb, &sock_hash_rx, &key, 0);
}

char _license[] SEC("license") = "GPL";
