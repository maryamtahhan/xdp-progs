/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>

/* cat /sys/kernel/debug/tracing/trace_pipe */
#define _bpf_printk(fmt, ...)                              \
({                                                         \
    char ____fmt[] = fmt;                                  \
    bpf_trace_printk(____fmt, sizeof(____fmt),             \
                         ##__VA_ARGS__);                   \
})

struct xdp_hints_common {
    union {
        __wsum        csum;
        struct {
            __u16    csum_start;
            __u16    csum_offset;
        };
    };
    __u16 rx_queue;
    __u16 vlan_tci;
    __u32 rx_hash32;
    __u32 xdp_hints_flags;
    __u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

struct xdp_hints {
    __u16 rss_type;
    struct xdp_hints_common common;
};

struct xdp_hints_timestamp {
    __u64 rx_timestamp;
    struct xdp_hints base;
};

__u32 get_btf_id(void *data)
{
    __u32 id = 0;

    bpf_core_read(&id, sizeof(__u32), data - sizeof(__u32));

    return id;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ixgbe_hints_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ixgbe_hints_rx_ts_map SEC(".maps");

SEC("xdp_proc_hints")
int  xdp_proc_hints_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    // void *data_end = (void *)(long)ctx->data_end;
    void *data_meta = (void *)(long)ctx->data_meta;

    int map_index = 0;
    __u32 *xdp_hints_value, *xdp_hints_rx_ts_value;

    xdp_hints_value = bpf_map_lookup_elem(&ixgbe_hints_map, &map_index);
    if (!xdp_hints_value) {
        goto out;
    }
    map_index = 0;

    xdp_hints_rx_ts_value = bpf_map_lookup_elem(&ixgbe_hints_rx_ts_map, &map_index);
    if (!xdp_hints_rx_ts_value) {
        goto out;
    }

    __u32 _btf_id = get_btf_id(data);

    if(_btf_id == *xdp_hints_value) {
        struct xdp_hints *xdp_hints = data_meta;

        if(xdp_hints + 1 > data)
            goto out;

		_bpf_printk("xdp_hints->rss_type = %d hash=%u", xdp_hints->rss_type, xdp_hints->common.rx_hash32);

    } else if(_btf_id == *xdp_hints_rx_ts_value) {
        struct xdp_hints_timestamp *xdp_hints_ts = data_meta;

        if(xdp_hints_ts + 1 > data)
            goto out;

        _bpf_printk("xdp_hints_ts->rx_timestamp = %llu", xdp_hints_ts->rx_timestamp);
    }

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
