extern crate cc;
use std::env;

fn main() {
    // macos currently can't deal with assembly
    if std::env::consts::OS == "linux" {
        env::set_var("CC", "gcc");

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
}

#[allow(unused)]
fn lkl_includes() {
    // Linux Kernel:
    println!("cargo:rustc-link-lib=static=linux");
}
