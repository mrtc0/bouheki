SHELL := /bin/bash -o pipefail
KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_BUILDDIR := pkg/bpf/bytecode
INCLUDES :=
BASEDIR = $(abspath)
OUTPUT = ./output
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CGO_ENABLED=1 CGO_CFLAGS="-I$(abspath $(OUTPUT))" CGO_LDFLAGS="-Wl,-Bstatic -Wl,-Bdynamic,-lelf,-lz $(LIBBPF_OBJ)"

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	cp -r libbpf output/

	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPF_BUILDDIR):
	mkdir -p $(BPF_BUILDDIR)

$(BPF_BUILDDIR)/%.bpf.o: pkg/bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

.PHONY: bpf-restricted-network
bpf-restricted-network: $(BPF_BUILDDIR)/restricted-network.bpf.o

.PHONY: bpf-restricted-file
bpf-restricted-file: $(BPF_BUILDDIR)/restricted-file.bpf.o

.PHONY: vmlinux
vmlinux:
	$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

.PHONY: build
build: bpf-restricted-network bpf-restricted-file
	$(CGOFLAG) go build -ldflags '-w -s' -o bouheki cmd/bouheki/bouheki.go

.PHONY: test
test: bpf-restricted-network bpf-restricted-file
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: test/integration
test/integration: bpf-restricted-network bpf-restricted-file
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E gotestsum -- --tags=integration --mod=vendor -bench=^$$ -race ./...

.PHONY: test/integration/specify
test/integration/specify: bpf-restricted-network bpf-restricted-file
	which gotestsum || go install gotest.tools/gotestsum@latest
	$(CGOFLAG) sudo -E go test -tags integration -run ${NAME} ./...

.PHONY: release
release:
	goreleaser release --rm-dist
