# BassetHound

BassetHound is a forensics utility designed to detect hidden processes and rootkits on Linux systems. 

This codebase is designed exclusively for Linux hosts, using **Rust** for the userland scanner, combined with a **Netlink-based Linux Kernel Module (LKM)** and an **eBPF Task Iterator** in kernel space.

---

## How It Works

BassetHound compares multiple sources of truth to identify process anomalies (discrepancies):

1. **Userland Listing (`proc_readdir`)**: Reads the `/proc` directory structure using directory listing.
2. **Userland Tools (`ps`)**: Captures and parses output of the system `ps` command (helps detect modified `ps` binaries or `LD_PRELOAD` hooks).
3. **Raw Probes (`proc_direct`)**: Directly queries individual `/proc/<pid>` directories without listing `/proc`.
4. **Syscall Brute Force (`syscalls`)**: Brute-forces PIDs (from 1 to `pid_max`) using non-destructive syscalls (`kill(pid, 0)`, `getpgid`, `getsid`, and `sched_getscheduler`).
5. **Kernel Module (`lkm`)**: A custom kernel module walks the kernel task list (`for_each_process`) and streams findings to userland via Netlink sockets.
6. **eBPF Iterator (`ebpf`)**: Runs a `bpf_iter/task` program to query running processes directly from the kernel BPF subsystem.

### Deep Syscall Audit
If any process discrepancy is found (e.g. a PID exists in the kernel task list or raw syscalls but is missing from `/proc`), BassetHound executes a **Deep Syscall Audit** on that specific suspicious PID. It audits the PID against 8 process and filesystem APIs to determine exactly how it is hiding:
* `kill(0)` signal API
* `getpgid()` process group API
* `getsid()` session API
* `sched_getscheduler()` scheduling policy
* `stat` on `/proc/<pid>`
* `open` on `/proc/<pid>/status`
* `readlink` on `/proc/<pid>/exe`
* `readdir` on `/proc/<pid>/task` (thread directory)

---

## Requirements

### Rust Toolchain
To compile the userland tool, install the Rust toolchain (Rust Edition 2024 or later):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### LKM Compilation Headers
To compile the kernel module, you need kernel headers for your running kernel on the target Linux system.
* **Ubuntu/Debian**:
  ```bash
  sudo apt-get install build-essential linux-headers-$(uname -r)
  ```
* **CentOS/RHEL/Fedora**:
  ```bash
  sudo dnf install kernel-devel
  ```

### eBPF Prerequisites
To build and run the eBPF task iterator (requires kernel 5.8+):
* `clang` (version 10+)
* `bpftool` (usually packaged as `linux-tools-common` or `bpftool`)

---

## Building

Everything must be compiled natively on a Linux host:

```bash
# Compile the userland binary, the kernel module, and the BPF program
make

# Build individual targets:
make userland   # Build the Rust userland scanner
make lkm        # Build the LKM kernel module (basset_hound_module.ko)
make ebpf       # Compile BPF task iterator bytecode (bpf/basset_hound.bpf.o)
make vmlinux    # Generate vmlinux.h from the running kernel
make clean      # Clean up build artifacts
```

---

## Running

Run the scanner as root/sudo to ensure it can probe low-level syscalls:

```bash
# Basic userland-only discrepancy scan
sudo ./target/release/basset_hound

# Load LKM and scan using Netlink
sudo insmod basset_hound_module.ko
sudo ./target/release/basset_hound --use-lkm

# Scan using eBPF task iterator
sudo ./target/release/basset_hound --use-ebpf

# Scan using all available interfaces
sudo ./target/release/basset_hound --use-lkm --use-ebpf
```

### CLI Arguments
* `-l`, `--use-lkm`       : Enable kernel module check via Netlink socket.
* `-e`, `--use-ebpf`      : Enable eBPF task iterator check.
* `-p`, `--pid-max <max>`  : Maximum PID limit to brute force (defaults to system `pid_max`).
* `-v`, `--verbose`        : Output verbose listing of all scanned PIDs.

---

## Testing

Run tests natively on Linux:
```bash
cargo test
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
