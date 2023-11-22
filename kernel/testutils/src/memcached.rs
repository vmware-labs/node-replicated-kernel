// Copyright © 2023 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::fs::remove_file;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use rexpect::errors::*;
use rexpect::session::{spawn_command, PtySession};

pub const MEMCACHED_MEM_SIZE_MB: usize = 4 * 1024;
pub const MEMCACHED_NUM_QUERIES: usize = 10_000_000;

pub const RACKSCALE_MEMCACHED_CSV_COLUMNS: &str =
    "git_rev,benchmark,os,protocol,npieces,nthreads,mem,queries,time,thpt\n";

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

pub fn linux_spawn_memcached(
    id: usize,
    config: &MemcachedShardedConfig,
    timeout_ms: u64,
) -> Result<PtySession> {
    let con_info = if config.protocol == "tcp" {
        format!("tcp://localhost:{}", 11212 + id)
    } else {
        let pathname = config.path.join(format!("memcached{id}.sock"));
        if pathname.is_file() {
            remove_file(pathname.clone()).expect("Failed to remove path"); // make sure the socket file is removed
        }
        format!("unix://{}", pathname.display())
    };

    let mut command = Command::new("bash");

    command.args(&[
        "scripts/spawn-memcached-process.sh",
        id.to_string().as_str(),
        con_info.as_str(),
        (2 * config.mem_size).to_string().as_str(),
        config.num_threads.to_string().as_str(),
    ]);
    command.current_dir(config.path.as_path());

    println!("Spawning memcached:\n $ `{:?}`", command);

    let mut res = spawn_command(command, Some(timeout_ms))?;
    std::thread::sleep(Duration::from_secs(1));

    match res.exp_regex(r#"INTERNAL BENCHMARK CONFIGURE"#) {
        Ok((_prev, _matched)) => {
            println!(" $ OK.");
            Ok(res)
        }
        Err(e) => {
            println!(" $ FAILED. {}", e);
            Err(e)
        }
    }
}

pub fn spawn_loadbalancer(config: &MemcachedShardedConfig, timeout_ms: u64) -> Result<PtySession> {
    let mut command = Command::new("./loadbalancer/loadbalancer");
    command.args(&["--binary"]);
    command.arg(format!("--num-queries={}", config.num_queries).as_str());
    command.arg(format!("--num-threads={}", config.num_threads).as_str());
    command.arg(format!("--max-memory={}", config.mem_size).as_str());
    let mut servers = String::from("--servers=");
    for i in 0..config.num_servers {
        if i > 0 {
            servers.push_str(",");
        }
        if config.protocol == "tcp" {
            if config.is_local_host {
                servers.push_str(format!("tcp://localhost:{}", 11212 + i).as_str());
            } else {
                // +1 because tap0 is reserved for the controller.
                let ip = 10 + i + 1;
                servers.push_str(format!("tcp://172.31.0.{}:{}", ip, 11211).as_str());
            }
        } else {
            servers
                .push_str(format!("unix://{}/memcached{}.sock", config.path.display(), i).as_str());
        }
    }
    command.arg(servers.as_str());
    command.current_dir(config.path.as_path());

    // give the servers some time to be spawned
    std::thread::sleep(Duration::from_secs(5));

    println!("Spawning Loadbalancer: \n $ `{:?}`", command);

    spawn_command(command, Some(timeout_ms))
}
