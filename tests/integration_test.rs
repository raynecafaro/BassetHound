use std::path::PathBuf;
use std::process::Command;

/// Helper to get the path of the compiled basset_hound binary
fn get_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    // Navigate out of target/debug/deps/
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("basset_hound");
    path
}

#[test]
fn test_help_flag() {
    let bin_path = get_binary_path();
    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);

    let output = Command::new(bin_path)
        .arg("--help")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BassetHound - Modernized Hidden Process Detector"));
    assert!(stdout.contains("--use-lkm"));
    assert!(stdout.contains("--use-ebpf"));
}

#[test]
fn test_standard_scan_execution() {
    let bin_path = get_binary_path();
    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);

    let output = Command::new(bin_path)
        .arg("--pid-max")
        .arg("100")
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BASSETHOUND PROCESS SCANNER"));
    assert!(stdout.contains("Scanning PID range"));
    assert!(stdout.contains("Running discrepancy analysis"));
}

#[test]
fn test_lkm_mode_execution() {
    let bin_path = get_binary_path();
    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);

    let output = Command::new(bin_path)
        .arg("--pid-max")
        .arg("50")
        .arg("--use-lkm")
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Querying Linux Kernel Module via Netlink..."));
    if std::env::var("CI").is_ok() || std::env::var("RUN_REAL_TESTS").is_ok() {
        assert!(
            stdout.contains("Querying Linux Kernel Module via Netlink... OK ("),
            "LKM query failed. Stdout:\n{}",
            stdout
        );
    }
}

#[test]
fn test_ebpf_mode_execution() {
    let bin_path = get_binary_path();
    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);

    let output = Command::new(bin_path)
        .arg("--pid-max")
        .arg("50")
        .arg("--use-ebpf")
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Querying eBPF task iterator..."));
    if std::env::var("CI").is_ok() || std::env::var("RUN_REAL_TESTS").is_ok() {
        assert!(
            stdout.contains("Querying eBPF task iterator... OK ("),
            "eBPF query failed. Stdout:\n{}",
            stdout
        );
    }
}

#[test]
fn test_combined_mode_execution() {
    let bin_path = get_binary_path();
    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);

    let output = Command::new(bin_path)
        .arg("--pid-max")
        .arg("50")
        .arg("--use-lkm")
        .arg("--use-ebpf")
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Querying Linux Kernel Module via Netlink..."));
    assert!(stdout.contains("Querying eBPF task iterator..."));
    if std::env::var("CI").is_ok() || std::env::var("RUN_REAL_TESTS").is_ok() {
        assert!(
            stdout.contains("Querying Linux Kernel Module via Netlink... OK ("),
            "LKM query failed. Stdout:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Querying eBPF task iterator... OK ("),
            "eBPF query failed. Stdout:\n{}",
            stdout
        );
    }
}
