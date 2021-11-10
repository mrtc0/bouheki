SHELL := /bin/bash -o pipefail
KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_BUILDDIR := pkg/bpf/bytecode
INCLUDES :=
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lbpf -Wl,-Bdynamic"

$(BPF_BUILDDIR):
	mkdir -p $(BPF_BUILDDIR)

$(BPF_BUILDDIR)/%.bpf.o: pkg/bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

.PHONY: bpf-restricted-network
bpf-restricted-network: $(BPF_BUILDDIR)/restricted-network.bpf.o

vmlinux:
	$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

.PHONY: build
build: bpf-restricted-network
	$(CGOFLAG) go build -ldflags '-w -s' -o bouheki cmd/bouheki/bouheki.go

.PHONY: test
test: bpf-restricted-network
	CGO_LDFLAGS="-lbpf" sudo -E go test -v ./...

.PHONY: release
release:
	goreleaser release --rm-dist
