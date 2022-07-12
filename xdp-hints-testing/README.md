# xdp-hints-test

This application relies on on the patches:

- The patches @ https://patchwork.kernel.org/project/netdevbpf/list/?series=654696&state=*&archive=both
- The patches in this directory

For this test we will redirect traffic from the ixgbe driver with xdp hints
enabled to a veth pair. We will attach an xdp program on the veth pair to
lookup the btf id and then use the right struct for ctx->data_meta.

First: Create veth pair and enabled link up:

```bash
ip link add veth1 type veth peer name veth2
ip link set veth1 up
ip link set veth2 up
```

Disable GRO/GSO/TSO on the veth devices

```bash
ethtool -K veth1 gso off gro off tso off
ethtool -K veth2 gso off gro off tso off
```

Load the BPF program and update the maps with the BTF ids for the ixgbe hints
structures (as there's no helper to allow us to look up the BTF id).

```bash
 ./xdp_loader -d veth2 --progsec xdp_proc_hints --force
 ./update-hints-maps
```

> **_NOTE_** the xdp_proc_hints bpf program creates 2 bpf maps that are filled
in through the `update-hints-maps` application.

Setup redirection from the ixgbe interface to the veth pair

```bash
cd <path to>/net-next/samples/bpf/
./xdp_redirect_map eno1 veth1
```

Send traffic through the interface and check the output from _bpf_printk

```bash
 cat /sys/kernel/debug/tracing/trace_pipe
```
