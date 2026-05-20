use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::fs;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use nix::unistd::{getpgid, getsid};
use nix::errno::Errno;
use nix::sched::sched_getscheduler;

/// Probe a PID using multiple non-destructive syscalls (like unhide)
pub fn probe_pid_syscalls(pid: i32) -> bool {
    let target_pid = Pid::from_raw(pid);

    // 1. kill(pid, 0) - Null signal check
    match kill(target_pid, None) {
        Ok(_) => return true,
        Err(Errno::EPERM) => return true, // exists, just no permission
        Err(Errno::ESRCH) => {},
        Err(_) => {},
    }

    // 2. getpgid(pid) - Get process group ID
    match getpgid(Some(target_pid)) {
        Ok(_) => return true,
        Err(Errno::EPERM) => return true,
        Err(Errno::ESRCH) => {},
        Err(_) => {},
    }

    // 3. getsid(pid) - Get session ID
    match getsid(Some(target_pid)) {
        Ok(_) => return true,
        Err(Errno::EPERM) => return true,
        Err(Errno::ESRCH) => {},
        Err(_) => {},
    }

    // 4. sched_getscheduler(pid) - Get scheduler policy
    {
        match sched_getscheduler(target_pid) {
            Ok(_) => return true,
            Err(Errno::EPERM) => return true,
            Err(Errno::ESRCH) => {},
            Err(_) => {},
        }
    }

    false
}

/// Run ps command and parse PIDs and names
pub fn scan_ps_command() -> Result<HashMap<i32, String>, String> {
    let output = Command::new("ps")
        .args(&["-e", "-o", "pid,comm"])
        .output()
        .map_err(|e| format!("Failed to execute ps command: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "ps command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut pids = HashMap::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pid) = parts[0].parse::<i32>() {
                let comm = parts[1..].join(" ");
                pids.insert(pid, comm);
            }
        }
    }
    Ok(pids)
}

#[derive(Default)]
pub struct ScanResults {
    pub proc_readdir: HashSet<i32>,
    pub proc_direct: HashSet<i32>,
    pub syscalls: HashSet<i32>,
    pub ps_cmds: HashMap<i32, String>,
    pub lkm: Option<HashMap<i32, String>>,
    pub ebpf: Option<HashMap<i32, String>>,
}

pub struct DetectionReport {
    pub hidden_processes: Vec<HiddenProcessDetail>,
    pub total_scanned: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SyscallAuditReport {
    pub kill_zero: Result<bool, String>,
    pub getpgid: Result<bool, String>,
    pub getsid: Result<bool, String>,
    pub sched_getscheduler: Result<bool, String>,
    pub stat_proc_dir: Result<bool, String>,
    pub open_status: Result<bool, String>,
    pub readlink_exe: Result<bool, String>,
    pub readdir_task: Result<bool, String>,
}

pub struct HiddenProcessDetail {
    pub pid: i32,
    pub name: String,
    pub detected_by: Vec<String>,
    pub hidden_from: Vec<String>,
    pub description: String,
    pub audit: SyscallAuditReport,
}

/// Audit a flagged PID against multiple process interaction APIs and syscalls
pub fn audit_process(pid: i32) -> SyscallAuditReport {
    let target_pid = Pid::from_raw(pid);

    // 1. kill(0)
    let kill_zero = match kill(target_pid, None) {
        Ok(_) => Ok(true),
        Err(Errno::EPERM) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 2. getpgid
    let getpgid_res = match getpgid(Some(target_pid)) {
        Ok(_) => Ok(true),
        Err(Errno::EPERM) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 3. getsid
    let getsid_res = match getsid(Some(target_pid)) {
        Ok(_) => Ok(true),
        Err(Errno::EPERM) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 4. sched_getscheduler
    let sched_res = match sched_getscheduler(target_pid) {
        Ok(_) => Ok(true),
        Err(Errno::EPERM) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 5. stat /proc/<pid>
    let stat_res = match fs::metadata(format!("/proc/{}", pid)) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 6. open /proc/<pid>/status
    let open_res = match fs::File::open(format!("/proc/{}/status", pid)) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 7. readlink /proc/<pid>/exe
    let readlink_res = match fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    // 8. readdir /proc/<pid>/task
    let readdir_res = match fs::read_dir(format!("/proc/{}/task", pid)) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    };

    SyscallAuditReport {
        kill_zero,
        getpgid: getpgid_res,
        getsid: getsid_res,
        sched_getscheduler: sched_res,
        stat_proc_dir: stat_res,
        open_status: open_res,
        readlink_exe: readlink_res,
        readdir_task: readdir_res,
    }
}

pub fn analyze_results(results: &ScanResults) -> DetectionReport {
    let mut hidden = Vec::new();

    // Union of all PIDs discovered across all sources
    let mut all_pids = HashSet::new();
    all_pids.extend(&results.proc_readdir);
    all_pids.extend(&results.proc_direct);
    all_pids.extend(&results.syscalls);
    all_pids.extend(results.ps_cmds.keys());
    if let Some(ref lkm_map) = results.lkm {
        all_pids.extend(lkm_map.keys());
    }
    if let Some(ref ebpf_map) = results.ebpf {
        all_pids.extend(ebpf_map.keys());
    }

    for &pid in &all_pids {
        // Exclude the detector program's PID itself to prevent noise if it creates short-lived tasks
        if pid == std::process::id() as i32 {
            continue;
        }

        let in_readdir = results.proc_readdir.contains(&pid);
        let in_direct = results.proc_direct.contains(&pid);
        let in_syscalls = results.syscalls.contains(&pid);
        let in_ps = results.ps_cmds.contains_key(&pid);
        let in_lkm = results.lkm.as_ref().map_or(false, |m| m.contains_key(&pid));
        let in_ebpf = results.ebpf.as_ref().map_or(false, |m| m.contains_key(&pid));

        let mut detected_by = Vec::new();
        let mut hidden_from = Vec::new();

        if in_readdir { detected_by.push("proc_readdir".to_string()); } else { hidden_from.push("proc_readdir".to_string()); }
        if in_direct { detected_by.push("proc_direct".to_string()); } else { hidden_from.push("proc_direct".to_string()); }
        if in_syscalls { detected_by.push("syscalls".to_string()); } else { hidden_from.push("syscalls".to_string()); }
        if in_ps { detected_by.push("ps".to_string()); } else { hidden_from.push("ps".to_string()); }

        if results.lkm.is_some() {
            if in_lkm { detected_by.push("lkm".to_string()); } else { hidden_from.push("lkm".to_string()); }
        }
        if results.ebpf.is_some() {
            if in_ebpf { detected_by.push("ebpf".to_string()); } else { hidden_from.push("ebpf".to_string()); }
        }

        // A process is flagged as hidden if it is visible in at least one kernel/syscall check but missing in userland directories or tools.
        let is_hidden = if hidden_from.is_empty() {
            false
        } else {
            // Visible via kernel module, eBPF, raw direct check, or syscall brute force,
            // but missing from /proc readdir or the ps tool.
            let visible_in_low_level = in_direct || in_syscalls || in_lkm || in_ebpf;
            let hidden_in_high_level = !in_readdir || !in_ps;
            visible_in_low_level && hidden_in_high_level
        };

        if is_hidden {
            // Find name
            let name = if let Some(ref lkm_map) = results.lkm {
                lkm_map.get(&pid).cloned()
            } else if let Some(ref ebpf_map) = results.ebpf {
                ebpf_map.get(&pid).cloned()
            } else if let Some(n) = results.ps_cmds.get(&pid) {
                Some(n.clone())
            } else {
                // Try reading /proc/<pid>/comm or status if it exists
                Some(std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()))
            };

            let name = name.unwrap_or_else(|| "unknown".to_string());

            // Determine description
            let description = if !in_readdir && !in_ps && (in_syscalls || in_direct) {
                "Kernel-level process hiding detected (getdents hook / rootkit)".to_string()
            } else if in_readdir && !in_ps {
                "Userland utility hijack detected (ps binary modified or LD_PRELOAD hook)".to_string()
            } else if !in_readdir && !in_syscalls && (in_lkm || in_ebpf) {
                "Sophisticated kernel rootkit hiding from standard syscalls but found via kernel traversal".to_string()
            } else {
                "Inconsistent process visibility across APIs".to_string()
            };

            // Run deep syscall audit for this hidden process
            let audit = audit_process(pid);

            hidden.push(HiddenProcessDetail {
                pid,
                name,
                detected_by,
                hidden_from,
                description,
                audit,
            });
        }
    }

    DetectionReport {
        hidden_processes: hidden,
        total_scanned: all_pids.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_system_no_hidden() {
        let mut results = ScanResults::default();
        results.proc_readdir.insert(1);
        results.proc_readdir.insert(100);

        results.proc_direct.insert(1);
        results.proc_direct.insert(100);

        results.syscalls.insert(1);
        results.syscalls.insert(100);

        results.ps_cmds.insert(1, "systemd".to_string());
        results.ps_cmds.insert(100, "bash".to_string());

        let report = analyze_results(&results);
        assert_eq!(report.hidden_processes.len(), 0);
        assert_eq!(report.total_scanned, 2);
    }

    #[test]
    fn test_kernel_level_hiding_detected() {
        let mut results = ScanResults::default();
        results.proc_readdir.insert(1);
        results.proc_direct.insert(1);
        results.proc_direct.insert(1234);
        results.syscalls.insert(1);
        results.syscalls.insert(1234);
        results.ps_cmds.insert(1, "systemd".to_string());

        let report = analyze_results(&results);
        assert_eq!(report.hidden_processes.len(), 1);
        assert_eq!(report.hidden_processes[0].pid, 1234);
        assert!(report.hidden_processes[0].description.contains("Kernel-level process hiding"));
        assert!(report.hidden_processes[0].hidden_from.contains(&"proc_readdir".to_string()));
        assert!(report.hidden_processes[0].hidden_from.contains(&"ps".to_string()));
    }

    #[test]
    fn test_userland_utility_hijack_detected() {
        let mut results = ScanResults::default();
        results.proc_readdir.insert(1);
        results.proc_readdir.insert(5555);
        results.proc_direct.insert(1);
        results.proc_direct.insert(5555);
        results.syscalls.insert(1);
        results.syscalls.insert(5555);
        results.ps_cmds.insert(1, "systemd".to_string());

        let report = analyze_results(&results);
        assert_eq!(report.hidden_processes.len(), 1);
        assert_eq!(report.hidden_processes[0].pid, 5555);
        assert!(report.hidden_processes[0].description.contains("Userland utility hijack"));
    }

    #[test]
    fn test_advanced_kernel_rootkit_detected() {
        let mut results = ScanResults::default();
        results.proc_readdir.insert(1);
        results.proc_direct.insert(1);
        results.syscalls.insert(1);
        results.ps_cmds.insert(1, "systemd".to_string());

        let mut lkm_map = HashMap::new();
        lkm_map.insert(1, "systemd".to_string());
        lkm_map.insert(9999, "backdoor".to_string());
        results.lkm = Some(lkm_map);

        let report = analyze_results(&results);
        assert_eq!(report.hidden_processes.len(), 1);
        assert_eq!(report.hidden_processes[0].pid, 9999);
        assert_eq!(report.hidden_processes[0].name, "backdoor");
        assert!(report.hidden_processes[0].description.contains("Sophisticated kernel rootkit"));
    }
}
