use libbpf_rs::ObjectBuilder;
use std::collections::HashMap;
use std::io::Read;

// Include the compiled BPF bytecode (copied to OUT_DIR by build.rs)
const BPF_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/basset_hound.bpf.o"));

/// Query process list from the embedded eBPF task iterator
pub fn query_ebpf() -> Result<HashMap<i32, String>, String> {
    if BPF_BYTES.is_empty() {
        return Err("eBPF task iterator bytecode was not compiled into this binary.".to_string());
    }

    let obj = ObjectBuilder::default()
        .open_memory(BPF_BYTES)
        .map_err(|e| format!("Failed to open BPF object from memory: {}", e))?;

    let mut loaded = obj
        .load()
        .map_err(|e| format!("Failed to load BPF program into kernel: {}", e))?;

    let prog = loaded
        .prog_mut("dump_task")
        .ok_or_else(|| "BPF program 'dump_task' not found in object".to_string())?;

    let link = prog
        .attach()
        .map_err(|e| format!("Failed to attach BPF task iterator link: {}", e))?;

    let mut iter = libbpf_rs::Iter::new(&link)
        .map_err(|e| format!("Failed to create BPF iterator reader: {}", e))?;

    let mut content = String::new();
    iter.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read from BPF task iterator: {}", e))?;

    let mut processes = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() == 2 {
            if let Ok(pid) = parts[0].parse::<i32>() {
                processes.insert(pid, parts[1].to_string());
            }
        }
    }

    Ok(processes)
}
