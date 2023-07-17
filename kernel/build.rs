// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

extern crate cc;

use std::env;
use std::process::Command;

fn main() {
    // macos currently can't deal with assembly
    if std::env::consts::OS == "linux" && env::var("TARGET").unwrap() == "x86_64-nrk" {
        env::set_var("CC", "gcc");
        println!("cargo:rerun-if-changed=src/arch/x86_64/start_ap.S");
        println!("cargo:rerun-if-changed=src/arch/x86_64/exec.S");
        println!("cargo:rerun-if-changed=src/arch/x86_64/acpi_printf.c");
        println!("cargo:rerun-if-changed=src/arch/x86_64/acpi_printf.h");

        cc::Build::new()
            .flag("-m64")
            .flag("-fno-builtin")
            .flag("-nostdlib")
            .flag("-U__linux__")
            .flag("-shared")
            .flag("-nostartfiles")
            .flag("-fPIC")
            .flag("-Wno-unused-parameter")
            .file("src/arch/x86_64/start_ap.S")
            .file("src/arch/x86_64/exec.S")
            .file("src/arch/x86_64/acpi_printf.c")
            .pic(true)
            .warnings(true)
            //.cargo_metadata(false)
            .compile("nrk_asm");
    }

    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Could not determine git hash");
    let git_hash = String::from_utf8(output.stdout).expect("Could not parse the git hash");
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
