// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
extern crate cc;

use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .expect("Could not determine git hash");
    let git_hash = String::from_utf8(output.stdout).expect("Could not parse the git hash");
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
