use clap::Parser;
use std::collections::HashSet;
use std::process::exit;

mod detector;
mod ebpf;
mod lkm;
mod procfs;

#[derive(Parser, Debug)]
#[command(author, version, about = "BassetHound - Modernized Hidden Process Detector", long_about = None)]
struct Args {
    /// Enable kernel module (LKM) check via Netlink socket
    #[arg(short = 'l', long)]
    use_lkm: bool,

    /// Enable eBPF task iterator check
    #[arg(short = 'e', long)]
    use_ebpf: bool,

    /// Maximum PID to scan during brute-force search (defaults to /proc/sys/kernel/pid_max)
    #[arg(short = 'p', long)]
    pid_max: Option<i32>,

    /// Show verbose scan details
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    // Check for root privileges
    let is_root = nix::unistd::getuid().is_root();
    if !is_root {
        println!("\x1b[1;33mWARNING: BassetHound is not running as root.\x1b[0m");
        println!(
            "Some checks (like eBPF loading, LKM communication, and certain direct process queries)"
        );
        println!(
            "require root privileges. It is highly recommended to run this utility via sudo.\n"
        );
    }

    println!("\x1b[1;36m====================================================\x1b[0m");
    println!("\x1b[1;36m             BASSETHOUND PROCESS SCANNER            \x1b[0m");
    println!("\x1b[1;36m====================================================\x1b[0m");

    // Determine PID max
    let pid_limit = args.pid_max.unwrap_or_else(procfs::get_pid_max);
    println!("Scanning PID range: 1 to {}...", pid_limit);

    let mut results = detector::ScanResults::default();

    // 1. Scan ProcFS readdir
    print!("Scanning /proc directory... ");
    match procfs::scan_proc_readdir() {
        Ok(pids) => {
            println!("OK ({} processes found)", pids.len());
            results.proc_readdir = pids;
        }
        Err(e) => {
            println!("FAILED ({})", e);
        }
    }

    // 2. Scan ps command
    print!("Parsing system ps output... ");
    match detector::scan_ps_command() {
        Ok(pids) => {
            println!("OK ({} processes found)", pids.len());
            results.ps_cmds = pids;
        }
        Err(e) => {
            println!("FAILED ({})", e);
        }
    }

    // 3. Syscall brute force and direct proc probes
    print!("Performing multi-syscall brute force and direct proc probes... ");
    let mut syscall_pids = HashSet::new();
    let mut direct_pids = HashSet::new();

    for pid in 1..=pid_limit {
        if detector::probe_pid_syscalls(pid) {
            syscall_pids.insert(pid);
        }
        // Direct probe /proc/<pid>
        let path = format!("/proc/{}", pid);
        if std::path::Path::new(&path).exists() {
            direct_pids.insert(pid);
        }
    }
    println!("OK");
    println!(
        "  - Syscall brute force: found {} active PIDs",
        syscall_pids.len()
    );
    println!(
        "  - Direct ProcFS probe: found {} active PIDs",
        direct_pids.len()
    );

    results.syscalls = syscall_pids;
    results.proc_direct = direct_pids;

    // 4. Scan LKM via Netlink
    if args.use_lkm {
        print!("Querying Linux Kernel Module via Netlink... ");
        match lkm::query_lkm() {
            Ok(pids) => {
                println!("OK ({} processes exported from kernel)", pids.len());
                results.lkm = Some(pids);
            }
            Err(e) => {
                println!("FAILED ({})", e);
            }
        }
    }

    // 5. Scan eBPF iterator
    if args.use_ebpf {
        print!("Querying eBPF task iterator... ");
        match ebpf::query_ebpf() {
            Ok(pids) => {
                println!("OK ({} processes returned from BPF)", pids.len());
                results.ebpf = Some(pids);
            }
            Err(e) => {
                println!("FAILED ({})", e);
            }
        }
    }

    println!("\x1b[1;36m----------------------------------------------------\x1b[0m");
    println!("Running discrepancy analysis...");
    let report = detector::analyze_results(&results);

    if report.hidden_processes.is_empty() {
        println!(
            "\n\x1b[1;32m[✓] SUCCESS: No hidden processes or rootkit signatures detected.\x1b[0m"
        );
        println!(
            "Total unique processes scanned across all interfaces: {}",
            report.total_scanned
        );
    } else {
        println!(
            "\n\x1b[1;31m[!] WARNING: Detected {} hidden process(es) / discrepancies!\x1b[0m",
            report.hidden_processes.len()
        );
        println!("\x1b[1;36m----------------------------------------------------\x1b[0m");

        for (i, proc) in report.hidden_processes.iter().enumerate() {
            println!("\x1b[1;31mDiscrepancy #{}\x1b[0m", i + 1);
            println!("  PID          : {}", proc.pid);
            println!("  Name         : \x1b[1m{}\x1b[0m", proc.name);
            println!("  Detected By  : {:?}", proc.detected_by);
            println!("  Hidden From  : {:?}", proc.hidden_from);
            println!("  Diagnosis    : \x1b[1;33m{}\x1b[0m", proc.description);
            println!("  Deep Syscall Audit:");
            print_audit_item("kill(0) signal", &proc.audit.kill_zero);
            print_audit_item("getpgid() group", &proc.audit.getpgid);
            print_audit_item("getsid() session", &proc.audit.getsid);
            print_audit_item("sched_getscheduler()", &proc.audit.sched_getscheduler);
            print_audit_item("stat /proc/<pid>", &proc.audit.stat_proc_dir);
            print_audit_item("open status file", &proc.audit.open_status);
            print_audit_item("readlink exe symlink", &proc.audit.readlink_exe);
            print_audit_item("readdir thread tasks", &proc.audit.readdir_task);
            println!();
        }

        println!("\x1b[1;36m====================================================\x1b[0m");
        println!(
            "\x1b[1;31mALERT: Hidden processes are a strong indicator of rootkit or malware activity.\x1b[0m"
        );
        exit(1);
    }

    // Verbose option for debugging
    if args.verbose {
        println!("\n\x1b[1;30mVerbose Active Process Map:\x1b[0m");
        let mut sorted_pids: Vec<&i32> = results.proc_readdir.iter().collect();
        sorted_pids.sort();
        for &pid in sorted_pids {
            let name = results
                .ps_cmds
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            println!("  [{}] {}", pid, name);
        }
    }
}

fn print_audit_item(name: &str, result: &Result<bool, String>) {
    match result {
        Ok(true) => println!("    - {:<20}: \x1b[1;32mVISIBLE\x1b[0m", name),
        Ok(false) => println!(
            "    - {:<20}: \x1b[1;31mHIDDEN\x1b[0m (Returned false)",
            name
        ),
        Err(e) => println!("    - {:<20}: \x1b[1;31mHIDDEN\x1b[0m ({})", name, e),
    }
}
