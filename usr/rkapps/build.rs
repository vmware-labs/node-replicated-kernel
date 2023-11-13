// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns true if all finalized app binaries exist, false otherwise.
fn apps_built(path: &Path) -> bool {
    let apps = build_plan();
    let mut all_app_binaries_exist = true;

    for (app, bake_out, bake_in, _unwind) in apps {
        let mut bake_out_path: PathBuf = path.into();
        bake_out_path.push(app);
        bake_out_path.push(bake_out);

        let mut bake_in_path: PathBuf = path.into();
        bake_in_path.push(app);
        bake_in_path.push(bake_in);

        all_app_binaries_exist =
            all_app_binaries_exist && bake_out_path.as_path().exists() && bake_out_path.exists();
    }

    all_app_binaries_exist
}

/// Returns a vector of build path information with an entry
/// for every application we want to build.
///
/// Format is: (folder_name, baking_output_binary, baking_input_binary)
///
/// The baking output binary should be placed in 'target/x86_64-nrk-none/debug|release/build'
/// (If you change this also don't forget to adapt the `run.py` script)
/// in the same location where static C library builds are stored
/// this goes slightly against convention that we shouldn't place
/// things out of OUT_DIR, but since we're abusing build.rs already anyways ¯\_(ツ)_/¯
fn build_plan() -> Vec<(&'static str, &'static str, &'static str, bool)> {
    let mut plan: Vec<(&'static str, &'static str, &'static str, bool)> = Default::default();

    let unwind_hack = true; // Adds -Wl,-allow-multiple-definition to rumprun-bake

    if cfg!(feature = "redis") {
        plan.push((
            "redis",
            "../../../../redis.bin",
            "bin/redis-server",
            !unwind_hack,
        ));
    }

    if cfg!(feature = "memcached") {
        plan.push((
            "memcached",
            "../../../../memcached.bin",
            "build/memcached",
            !unwind_hack,
        ));
    }

    if cfg!(feature = "nginx") {
        plan.push(("nginx", "../../../../nginx.bin", "bin/nginx", !unwind_hack));
    }

    if cfg!(feature = "memcached-bench") {
        plan.push((
            "memcached-bench",
            "../../../../memcachedbench.bin",
            "build/memcached",
            !unwind_hack,
        ));
    }

    if cfg!(feature = "leveldb-bench") {
        plan.push((
            "leveldb",
            "../../../../dbbench.bin",
            "bin/db_bench",
            unwind_hack,
        ));
    }

    if cfg!(feature = "monetdb") {
        plan.push((
            "monetdb",
            "../../../../monetdbd.bin",
            "build/bin/monetdbd",
            !unwind_hack,
        ));

        plan.push((
            "monetdb",
            "../../../../monetdb.bin",
            "build/bin/monetdb",
            !unwind_hack,
        ));
    }

    plan
}

/// Clones rumprun-packages repo and builds applications
fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_path = PathBuf::from(out_dir.clone());

    // Re-run in case we changed libvibrio.a
    let mut vib_path: PathBuf = out_dir_path.clone();
    vib_path.push("..");
    vib_path.push("..");
    vib_path.push("..");
    vib_path.push("..");
    vib_path.push("libvibrio.a");
    println!("cargo:rerun-if-changed={}", vib_path.as_path().display());

    println!("OUT_DIR {:?}", out_dir);
    let apps_built = apps_built(out_dir_path.as_path());

    if !apps_built {
        println!("RMDIR {:?}", out_dir);
        Command::new(format!("rm",))
            .args(&["-rf", out_dir.as_str()])
            .status()
            .unwrap();

        println!("MKDIR {:?}", out_dir);
        Command::new(format!("mkdir",))
            .args(&["-p", out_dir.as_str()])
            .status()
            .unwrap();

        println!("CLONE {:?}", out_dir);
        let url = "https://github.com/gz/librettos-packages.git";
        Command::new("git")
            .args(&["clone", "--depth=1", url, out_dir.as_str()])
            .status()
            .unwrap();

        println!(
            "CHECKOUT eece690294fbfed418f43034b5dc77290865f8cf {:?}",
            out_dir
        );
        Command::new("git")
            .args(&["checkout", "eece690294fbfed418f43034b5dc77290865f8cf"])
            .current_dir(&Path::new(&out_dir))
            .status()
            .unwrap();

        println!("BUILD {:?}", out_dir);
        for (key, value) in env::vars() {
            println!("{}: {}", key, value);
        }
    }

    let rump_env = env::var("DEP_RKAPPS_BIN_TARGET").expect("Need a rumpkernel target dir");
    let path_env = env::var("PATH").expect("We don't have PATH already set?");

    // Path to application directories we want to build
    let apps = build_plan();
    let cpus = format!("{}", num_cpus::get());

    for (app, bake_in, bake_out, unwind_hack) in apps {
        let build_args = &["-j", cpus.as_str()];
        let mut app_dir = out_dir_path.clone();
        app_dir.push(app);

        let path = format!("{}:{}", rump_env.clone(), path_env);
        let toolchain = "x86_64-rumprun-netbsd";
        let cmd = format!(
            "PATH={} RUMPRUN_TOOLCHAIN_TUPLE={} make {}",
            path,
            toolchain,
            build_args.join(" ")
        );
        println!("cd {:?}", app_dir.as_path());
        println!("{}", cmd);
        let status = Command::new("make")
            .args(build_args)
            .env("PATH", path.as_str())
            .env("RUMPRUN_TOOLCHAIN_TUPLE", toolchain)
            .current_dir(app_dir.as_path())
            .status()
            .expect("Can't make app dir");
        assert!(status.success(), "Can't make app dir");

        let bake_args = &["nrk_generic", bake_in, bake_out];
        println!(
            "PATH={} RUMPRUN_TOOLCHAIN_TUPLE={} rumprun-bake {}",
            path.as_str(),
            toolchain,
            bake_args.join(" ")
        );
        let status = if unwind_hack {
            Command::new("rumprun-bake")
                .args(bake_args)
                .env("PATH", path.as_str())
                .env("RUMPRUN_TOOLCHAIN_TUPLE", toolchain)
                .env("RUMPBAKE_ENV", "-Wl,-allow-multiple-definition")
                .current_dir(app_dir.as_path())
                .status()
                .expect("Can't bake binary")
        } else {
            Command::new("rumprun-bake")
                .args(bake_args)
                .env("PATH", path.as_str())
                .env("RUMPRUN_TOOLCHAIN_TUPLE", toolchain)
                .current_dir(app_dir.as_path())
                .status()
                .expect("Can't bake binary")
        };
        assert!(status.success(), "Can't bake binary");
    }

    println!("OUT_DIR {:?}", out_dir);
}
