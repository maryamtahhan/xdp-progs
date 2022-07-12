/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <getopt.h>
#include <time.h>
#include <bpf/btf.h>

#define pr_err(fmt, ...) \
    fprintf(stderr, "%s:%d - " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

static const char *file_ixgbe_hints_map = "/sys/fs/bpf/ixgbe_hints_map";
static const char *file_ixgbe_hints_rx_ts_map   = "/sys/fs/bpf/ixgbe_hints_rx_ts_map";
static const char *module_name = "ixgbe";
static const char *symbol_name_xdp_hints_ixgbe = "xdp_hints_ixgbe";
static const char *symbol_name_xdp_hints_ixgbe_timestamp = "xdp_hints_ixgbe_timestamp";

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0) {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
               file, errno, strerror(errno));
        exit(-1);
    }
    return fd;
}

int main(int argc, char **argv)
{
    int fd_ixgbe_hints_map;
    int fd_ixgbe_hints_rx_ts_map;
    int err = 0;
    struct btf *vmlinux_btf, *module_btf = NULL;
    __s32 type_id;
    __u32 key = 0;
    __u64 value;

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
        pr_err("ERROR(%d): btf__load_vmlinux_btf()\n", err);
        goto out;
    }

    module_btf = btf__load_module_btf(module_name, vmlinux_btf);
    err = libbpf_get_error(module_btf);
    if (err) {
        pr_err("ERROR(%d): btf__load_module_btf() module_name: %s\n",
               err, module_name);
        goto out;
    }

    type_id = btf__find_by_name(module_btf, symbol_name_xdp_hints_ixgbe);
    if (type_id < 0) {
        err = type_id;
        pr_err("ERROR(%d): btf__find_by_name() symbol_name: %s\n",
               err, symbol_name_xdp_hints_ixgbe);
        goto out;
    }

    printf("Module:%s Symbol:%s has BTF id:%d\n",
           module_name, symbol_name_xdp_hints_ixgbe, type_id);

    value = type_id;
    fd_ixgbe_hints_map = open_bpf_map(file_ixgbe_hints_map);
    bpf_map_update_elem(fd_ixgbe_hints_map, &key, &value, BPF_ANY);
    close(fd_ixgbe_hints_map);

        type_id = btf__find_by_name(module_btf, symbol_name_xdp_hints_ixgbe_timestamp);
    if (type_id < 0) {
        err = type_id;
        pr_err("ERROR(%d): btf__find_by_name() symbol_name: %s\n",
               err, symbol_name_xdp_hints_ixgbe_timestamp);
        goto out;
    }

    printf("Module:%s Symbol:%s has BTF id:%d\n",
           module_name, symbol_name_xdp_hints_ixgbe_timestamp, type_id);

    value = type_id;
    fd_ixgbe_hints_rx_ts_map = open_bpf_map(file_ixgbe_hints_rx_ts_map);
    bpf_map_update_elem(fd_ixgbe_hints_rx_ts_map, &key, &value, BPF_ANY);
    close(fd_ixgbe_hints_rx_ts_map);

out:
    btf__free(module_btf);
    btf__free(vmlinux_btf);
    if (err)
        return -1;
    return 0;
}