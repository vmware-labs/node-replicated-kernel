// Copyright © 2023 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use rexpect::errors::*;
use rexpect::session::PtySession;

pub const MEMCACHED_MEM_SIZE_MB: usize = 4 * 1024;
pub const MEMCACHED_NUM_QUERIES: usize = 1_000_000;

#[derive(Clone)]
pub struct MemcachedShardedConfig {
    pub num_servers: usize,
    pub num_queries: usize,
    pub is_local_host: bool,
    pub mem_size: usize,
    pub protocol: &'static str,
    pub num_threads: usize,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct MemcachedResult {
    pub b_threads: String,
    pub b_mem: String,
    pub b_queries: String,
    pub b_time: String,
    pub b_thpt: String,
}

pub fn parse_memcached_output(p: &mut PtySession, output: &mut String) -> Result<MemcachedResult> {
    // x_benchmark_mem = 10 MB
    let (prev, matched) = p.exp_regex(r#"x_benchmark_mem = (\d+) MB"#)?;
    // println!("> {}", matched);
    let b_mem = matched.replace("x_benchmark_mem = ", "").replace(" MB", "");

    *output += prev.as_str();
    *output += matched.as_str();

    // number of threads: 3
    let (prev, matched) = p.exp_regex(r#"number of threads: (\d+)"#)?;
    // println!("> {}", matched);
    let b_threads = matched.replace("number of threads: ", "");

    *output += prev.as_str();
    *output += matched.as_str();

    // number of keys: 131072
    let (prev, matched) = p.exp_regex(r#"number of keys: (\d+)"#)?;
    // println!("> {}", matched);

    *output += prev.as_str();
    *output += matched.as_str();

    // benchmark took 129 seconds
    let (prev, matched) = p.exp_regex(r#"benchmark took (\d+) ms"#)?;
    // println!("> {}", matched);
    let b_time = matched.replace("benchmark took ", "").replace(" ms", "");

    *output += prev.as_str();
    *output += matched.as_str();

    // benchmark took 7937984 queries / second
    let (prev, matched) = p.exp_regex(r#"benchmark took (\d+) queries / second"#)?;
    println!("> {}", matched);
    let b_thpt = matched
        .replace("benchmark took ", "")
        .replace(" queries / second", "");

    *output += prev.as_str();
    *output += matched.as_str();

    let (prev, matched) = p.exp_regex(r#"benchmark executed (\d+)"#)?;
    println!("> {}", matched);
    let b_queries = matched
        .replace("benchmark executed ", "")
        .split(" ")
        .next()
        .unwrap()
        .to_string();

    *output += prev.as_str();
    *output += matched.as_str();

    if output.contains("MEMORY ALLOCATION FAILURE") {
        println!("Detected memory allocation error in memcached output");
        Err("Memory allocation failure".into())
    } else {
        Ok(MemcachedResult {
            b_threads,
            b_mem,
            b_queries,
            b_time,
            b_thpt,
        })
    }
}

#[cfg(not(feature = "baremetal"))]
pub fn rackscale_memcached_checkout(tmpdir: &str) {
    let out_dir_path = PathBuf::from(tmpdir).join("sharded-memcached");

    let out_dir = out_dir_path.display().to_string();

    println!("CARGO_TARGET_TMPDIR {:?}", out_dir);

    // clone abd build the benchmark
    if !out_dir_path.is_dir() {
        println!("RMDIR {:?}", out_dir_path);
        Command::new(format!("rm",))
            .args(&["-rf", out_dir.as_str()])
            .status()
            .unwrap();

        println!("MKDIR {:?}", out_dir_path);
        Command::new(format!("mkdir",))
            .args(&["-p", out_dir.as_str()])
            .status()
            .unwrap();

        println!("CLONE {:?}", out_dir_path);
        let url = "https://github.com/achreto/memcached-bench.git";
        Command::new("git")
            .args(&["clone", "--depth=1", url, out_dir.as_str()])
            .output()
            .expect("failed to clone");
    } else {
        Command::new("git")
            .args(&["pull"])
            .current_dir(out_dir_path.as_path())
            .output()
            .expect("failed to pull");
    }

    println!(
        "CHECKOUT a703eedd8032ff1e083e8c5972eacc95738c797b {:?}",
        out_dir
    );

    let res = Command::new("git")
        .args(&["checkout", "a703eedd8032ff1e083e8c5972eacc95738c797b"])
        .current_dir(out_dir_path.as_path())
        .output()
        .expect("git checkout failed");
    if !res.status.success() {
        std::io::stdout().write_all(&res.stdout).unwrap();
        std::io::stderr().write_all(&res.stderr).unwrap();
        panic!("git checkout failed!");
    }

    println!("BUILD {:?}", out_dir_path);
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let build_args = &["-j", "8"];

    // now build the benchmark
    let status = Command::new("make")
        .args(build_args)
        .current_dir(&out_dir_path)
        .output()
        .expect("Can't make app dir");

    if !status.status.success() {
        println!("BUILD FAILED");
        std::io::stdout().write_all(&status.stdout).unwrap();
        std::io::stderr().write_all(&status.stderr).unwrap();
        panic!("BUILD FAILED");
    }
}
