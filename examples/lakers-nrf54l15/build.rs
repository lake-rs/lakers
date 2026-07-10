use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

// Put `memory.x` where the linker can find it (cortex-m-rt's link.x does `INCLUDE memory.x`).
fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
}
