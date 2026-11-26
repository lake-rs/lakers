//! This build script copies the memory layout of the board selected by the
//! target into the output directory as `memory.x`, where the linker can always
//! find it at build time: `thumbv7em-none-eabihf` runs on the nRF52840, any
//! other target on the lm3s6965evb emulated by QEMU.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let memory = match env::var("TARGET").as_deref() {
        Ok("thumbv7em-none-eabihf") => "memory-nrf52840.x",
        _ => "memory-lm3s6965.x",
    };

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::copy(memory, out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=memory-nrf52840.x");
    println!("cargo:rerun-if-changed=memory-lm3s6965.x");

    // Set the linker script to the one provided by cortex-m-rt.
    println!("cargo:rustc-link-arg=-Tlink.x");
    // Set the extra linker script from defmt
    println!("cargo:rustc-link-arg=-Tdefmt.x");
}
