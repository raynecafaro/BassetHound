# Target declarations
.PHONY: all userland lkm ebpf clean vmlinux

all: userland lkm ebpf

# Build the Rust userland tool natively
userland:
	cargo build --release

# Build the Linux Kernel Module (LKM)
lkm:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Generate vmlinux.h for eBPF compilation
vmlinux:
	@mkdir -p bpf
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compile eBPF program to BPF bytecode
ebpf: bpf/basset_hound.bpf.o

bpf/basset_hound.bpf.o: bpf/basset_hound.bpf.c
	@mkdir -p bpf
	# Generate vmlinux.h if it doesn't exist
	@if [ ! -f bpf/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h || \
		(echo "Error: bpftool failed to generate vmlinux.h. Please make sure bpftool is installed." && exit 1); \
	fi
	clang -g -O2 -target bpf -I bpf/ -c bpf/basset_hound.bpf.c -o bpf/basset_hound.bpf.o

# Clean build artifacts
clean:
	cargo clean
	rm -f bpf/basset_hound.bpf.o
	@if [ -d /lib/modules/$(shell uname -r)/build ]; then \
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean; \
	fi

obj-m += basset_hound_module.o
