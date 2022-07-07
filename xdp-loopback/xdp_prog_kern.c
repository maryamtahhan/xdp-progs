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

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    __u16 h_proto;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    h_proto = eth->h_proto;

    return h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                       void *data_end,
                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    /* Sanity check packet field is valid */
    if(hdrsize < sizeof(*iph))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    //nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

/*
 * Swaps destination and source MAC addresses inside an Ethernet header
 */
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr, void *data_end)
{
	__be32 tmp = iphdr->saddr;

    // NEED TO CHECK HEADER FOR EACH PACKET ACCESS
	if (iphdr + 1 > data_end)
        return;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

SEC("xdp_lb")
int  xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;


    struct hdr_cursor nh;
    int nh_type;
    struct iphdr *iph;
    nh.pos = data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == bpf_htons(ETH_P_IP)) {
		swap_src_dst_mac(eth);
        parse_iphdr(&nh, data_end, &iph);
		swap_src_dst_ipv4(iph, data_end);
		return XDP_TX;
	}

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
