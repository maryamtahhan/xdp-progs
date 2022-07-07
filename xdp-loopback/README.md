# xdp-loopback

This is a simple xdp program that swaps:

1. src and dst MAC addresses
2. src and dst IP addresses

Then sends the packet back out on the same interface it came in.

To build simply `make` then load the xdp program `xdp_prog_kern.o`
with your preferred xdp loader.
