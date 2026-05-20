use std::fs;
use std::path::Path;

fn main() {
    // Re-run this build script if the compiled BPF object changes
    println!("cargo:rerun-if-changed=bpf/basset_hound.bpf.o");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("basset_hound.bpf.o");

    let src_path = Path::new("bpf/basset_hound.bpf.o");
    if src_path.exists() {
        if let Err(e) = fs::copy(src_path, &dest_path) {
            panic!("Failed to copy BPF object to OUT_DIR: {}", e);
        }
    } else {
        // If the BPF object has not been built (e.g. on systems without BTF support),
        // write an empty file so that Cargo can compile userland successfully.
        if let Err(e) = fs::write(&dest_path, []) {
            panic!("Failed to write dummy BPF object to OUT_DIR: {}", e);
        }
    }
}
