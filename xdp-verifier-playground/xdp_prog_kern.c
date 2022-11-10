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
#include <linux/udp.h>
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

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct udphdr **udphdr)
{
    int len;
    struct udphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos  = h + 1;
    *udphdr = h;

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    return len;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                       void *data_end,
                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl* 4;
    /* Sanity check packet field is valid */
    if(hdrsize < sizeof(*iph))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

SEC("xdp_filter")
int  xdp_filter_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;


    struct hdr_cursor nh;
    int nh_type, ip_type;
    struct iphdr *iph;

    nh.pos = data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
        if (ip_type == IPPROTO_UDP) {
            struct udphdr *h;
            if (parse_udphdr(&nh, data_end, &h) < 0)
                 return -1;

            if (h + 1 > data_end)
                return -1;

            if(h->dest == 1234) {
				// the scope of the tcp hdr whose address follows on from the ip header is
				// deemed to be ok. So there's no issues with accessing these fields.
                bpf_printk("Got IP packet: dest: %pI4, protocol: %u", &(iph->daddr), iph->protocol);
            }

        }
        // If you disable this check the verifier fails as iph validity hasn't been
		// checked anywhere else
         if (iph + 1 > data_end)
                 return -1;

        bpf_printk("Got IP packet: dest: %pI4, protocol: %u", &(iph->daddr), iph->protocol);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
