use std::collections::HashSet;
use std::fs;

/// Scan /proc directory using directory listing (readdir)
pub fn scan_proc_readdir() -> Result<HashSet<i32>, std::io::Error> {
    let mut pids = HashSet::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<i32>() {
                pids.insert(pid);
            }
        }
    }
    Ok(pids)
}

/// Query the max PID limit dynamically from the system
pub fn get_pid_max() -> i32 {
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/pid_max") {
        if let Ok(pid) = content.trim().parse::<i32>() {
            return pid;
        }
    }
    32768 // fallback
}
