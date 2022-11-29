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
	-O2 -emit-llvm -c -g -o sockhash_parser_kern.ll sockhash_parser_kern.c
	$(LLC) -march=bpf -filetype=obj -o sockhash_parser_kern.o sockhash_parser_kern.ll
	$(CLANG) -S \
	-target bpf \
	-D __BPF_TRACING__ \
	-I/usr/include/bpf \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-O2 -emit-llvm -c -g -o sockhash_verdict_kern.ll sockhash_verdict_kern.c
	$(LLC) -march=bpf -filetype=obj -o sockhash_verdict_kern.o sockhash_verdict_kern.ll

clean:
	rm -f *.o sockhash_parser_kern.ll sockhash_verdict_kern.ll