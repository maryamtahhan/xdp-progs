/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCKMAP_H_
#define _SOCKMAP_H_

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

#endif /* _SOCKMAP_H_ */