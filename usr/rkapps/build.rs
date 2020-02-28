use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use num_cpus;

/// Returns true if all finalized app binaries exist, false otherwise.
fn apps_built(path: &Path) -> bool {
    let apps = build_plan();
    let mut all_app_binaries_exist = true;

    for (app, bake_out, _bake_in) in apps {
        let mut append_path: PathBuf = path.clone().into();
        append_path.push(app);
        append_path.push(bake_out);

        all_app_binaries_exist = all_app_binaries_exist && append_path.as_path().exists();
    }

    all_app_binaries_exist
}

/// Returns a vector of build path information with an entry
/// for every application we want to build.
///
/// Format is: (folder_name, baking_output_binary, baking_input_binary)
///
/// The baking output binary should be placed in 'target/x86_64-bespin-none/debug|release/build'
/// (If you change this also don't forget to adapt the `run.sh` script)
/// in the same location where static C library builds are stored
/// this goes slightly against convention that we shouldn't place
/// things out of OUT_DIR, but since we're abusing build.rs already anyways ¯\_(ツ)_/¯
fn build_plan() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut plan: Vec<(&'static str, &'static str, &'static str)> = Default::default();
    if cfg!(feature = "redis") {
        plan.push(("redis", "../../../../redis.bin", "bin/redis-server"));
    }

    plan
}

/// Clones rumprun-packages repo and builds applications
fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_path = PathBuf::from(out_dir.clone());

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
        let url = "https://github.com/gz/rumprun-packages.git";
        Command::new("git")
            .args(&["clone", "--depth=1", url, out_dir.as_str()])
            .status()
            .unwrap();

        println!("BUILD {:?}", out_dir);
        for (key, value) in env::vars() {
            println!("{}: {}", key, value);
        }

        let rump_env = env::var("DEP_RKAPPS_BIN_TARGET").expect("Need a rumpkernel target dir");
        let path_env = env::var("PATH").expect("We don't have PATH already set?");

        // Path to application directories we want to build
        let apps = build_plan();
        let cpus = format!("{}", num_cpus::get());

        for (app, bake_in, bake_out) in apps {
            let build_args = &["-j", cpus.as_str()];
            let mut app_dir = out_dir_path.clone();
            app_dir.push(app);

            let status = Command::new("make")
                .args(build_args)
                .env("PATH", format!("{}:{}", rump_env.clone(), path_env))
                .env("RUMPRUN_TOOLCHAIN_TUPLE", "x86_64-rumprun-netbsd")
                .current_dir(app_dir.as_path())
                .status()
                .expect("Can't make app dir");
            assert!(status.success(), "Can't make app dir");

            // TODO: maybe we meed to make baking app specific
            let bake_args = &["bespin_generic", bake_in, bake_out];
            let status = Command::new("rumprun-bake")
                .args(bake_args)
                .env("PATH", format!("{}:{}", rump_env.clone(), path_env))
                .env("RUMPRUN_TOOLCHAIN_TUPLE", "x86_64-rumprun-netbsd")
                .current_dir(app_dir.as_path())
                .status()
                .expect("Can't bake binary");
            assert!(status.success(), "Can't bake binary");
        }

        println!("OUT_DIR {:?}", out_dir);
    }
}
