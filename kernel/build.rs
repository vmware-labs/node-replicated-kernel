extern crate cc;

use std::env;
use std::process::Command;

fn main() {
    // macos currently can't deal with assembly
    if std::env::consts::OS == "linux" {
        env::set_var("CC", "gcc");
        println!("cargo:rerun-if-changed=src/arch/x86_64/start_ap.S");
        println!("cargo:rerun-if-changed=src/arch/x86_64/exec.S");

        cc::Build::new()
            .flag("-m64")
            .flag("-fno-builtin")
            .flag("-nostdlib")
            .flag("-nostdinc")
            .flag("-U__linux__")
            .flag("-shared")
            .flag("-nostartfiles")
            .flag("-fPIC")
            .file("src/arch/x86_64/start_ap.S")
            .file("src/arch/x86_64/exec.S")
            .pic(true)
            .warnings(true)
            .compile("bespin_asm");
    }

    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .expect("Could not determine git hash");
    let git_hash = String::from_utf8(output.stdout).expect("Could not parse the git hash");
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}

#[allow(unused)]
fn lkl_includes() {
    // Linux Kernel:
    println!("cargo:rustc-link-lib=static=linux");
}
