# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LLC ?= llc
CLANG ?= clang

all: myprog

myprog:
	$(CLANG) -S \
	-target bpf \
	-D __BPF_TRACING__ \
	-I/usr/include/bpf \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-O2 -emit-llvm -c -g -o sockmap_parser_kern.ll sockmap_parser_kern.c
	$(LLC) -march=bpf -filetype=obj -o sockmap_parser_kern.o sockmap_parser_kern.ll
	$(CLANG) -S \
	-target bpf \
	-D __BPF_TRACING__ \
	-I/usr/include/bpf \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-O2 -emit-llvm -c -g -o sockmap_verdict_kern.ll sockmap_verdict_kern.c
	$(LLC) -march=bpf -filetype=obj -o sockmap_verdict_kern.o sockmap_verdict_kern.ll

clean:
	rm -f *.o sockmap_parser_kern.ll sockmap_verdict_kern.ll