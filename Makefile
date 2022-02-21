SHELL := /bin/bash -o pipefail
KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_BUILDDIR := pkg/bpf/bytecode
BPFCOV_BUILDDIR := bpfcov/build
BPFCOV_BASEDIR := bpfcov
INCLUDES :=
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lbpf -Wl,-Bdynamic"

$(BPF_BUILDDIR):
	mkdir -p $(BPF_BUILDDIR)

$(BPF_BUILDDIR)/%.bpf.o: pkg/bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(BPF_BUILDDIR)/%.bpf.ll: pkg/bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	/usr/lib/llvm-12/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -emit-llvm -S -c $(filter %.c,$^) -o $@

.PHONY: bpf-restricted-network
bpf-restricted-network: $(BPF_BUILDDIR)/restricted-network.bpf.o

.PHONY: vmlinux
vmlinux:
	$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

.PHONY: build
build: bpf-restricted-network
	$(CGOFLAG) go build -ldflags '-w -s' -o bouheki cmd/bouheki/bouheki.go

.PHONY: test
test: bpf-restricted-network
	which gotestsum || go install gotest.tools/gotestsum@latest
	CGO_LDFLAGS="-lbpf" sudo -E gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: release
release:
	goreleaser release --rm-dist

.PHONY: bpfcov
bpfcov: $(BPF_BUILDDIR)/restricted-network.bpf.ll
	mkdir -p $(BPFCOV_BUILDDIR)
	cd $(BPFCOV_BUILDDIR) && cmake -DLT_LLVM_INSTALL_DIR=/usr/lib/llvm-12 .. && make
	opt -load-pass-plugin $(BPFCOV_BUILDDIR)/lib/libBPFCov.so -passes="bpf-cov" -S $(BPF_BUILDDIR)/restricted-network.bpf.ll -o $(BPF_BUILDDIR)/restricted-network.bpf.cov.ll
