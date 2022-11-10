# xdp-filter-udp

This is a simple xdp program that filters UDP traffic
to an AF_XDP socket and all other traffic to the Linux
networking stack.

To build simply `make` then load the xdp program `xdp_prog_kern.o`
with your preferred xdp loader.

# References

https://github.com/xdp-project/xdp-tutorial/tree/master/packet01-parsing#packet-bounds-checking
