# Makefile for Nexus SFU XDP/BPF programs
# Requires: clang, llvm, libbpf-dev
#
# Usage:
#   make          - Build all BPF programs
#   make clean    - Remove build artifacts
#   make install  - Install to /usr/lib/bpf/

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# BPF compilation flags
BPF_CFLAGS := -O2 -g -Wall -Werror
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86

# Include paths for BPF headers
BPF_INCLUDES := -I/usr/include
BPF_INCLUDES += -I/usr/include/bpf

# Source files
BPF_SRCS := xdp_sfu.c
BPF_OBJS := $(BPF_SRCS:.c=.o)

# Installation directory
INSTALL_DIR := /usr/lib/bpf

.PHONY: all clean install

all: $(BPF_OBJS)

# Compile BPF C to object file
%.o: %.c
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Generate skeleton header (optional, for libbpf skeleton API)
%.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f $(BPF_OBJS) *.skel.h

install: $(BPF_OBJS)
	install -d $(INSTALL_DIR)
	install -m 644 $(BPF_OBJS) $(INSTALL_DIR)/

# Verify BPF program (useful for debugging)
verify: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		echo "Verifying $$obj..."; \
		$(BPFTOOL) prog load $$obj /sys/fs/bpf/test_$$(basename $$obj .o) 2>&1 || true; \
		rm -f /sys/fs/bpf/test_$$(basename $$obj .o); \
	done

# Show BPF program info
info: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		echo "=== $$obj ==="; \
		llvm-objdump -S $$obj | head -100; \
	done
