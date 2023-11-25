// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s11_*`: Rackscale (distributed) benchmarks
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use rexpect::errors::*;
use rexpect::session::PtySession;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{DCMConfig, DCMSolver};
use testutils::rackscale_runner::{RackscaleBench, RackscaleRun};
use testutils::runner_args::RackscaleTransport;

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_fxmark_benchmark() {
    rackscale_fxmark_benchmark(RackscaleTransport::Shmem);
}

#[test]
#[ignore]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_ethernet_fxmark_benchmark() {
    rackscale_fxmark_benchmark(RackscaleTransport::Ethernet);
}

#[derive(Clone)]
struct FxmarkConfig {
    open_files: usize,
    write_ratio: usize,
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_fxmark_benchmark(transport: RackscaleTransport) {
    let file_name = format!("rackscale_{}_fxmark_benchmark.csv", transport.to_string());
    let _ignore = std::fs::remove_file(file_name.clone());

    let config = FxmarkConfig {
        open_files: 1,
        write_ratio: 0,
    };

    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("fxmark")
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let built = build.build();

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        is_baseline: bool,
        _arg: Option<FxmarkConfig>,
    ) -> Result<()> {
        // Parse lines like
        // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
        // write them to a CSV file
        let expected_lines = if cfg!(feature = "smoke") {
            1
        } else {
            cores_per_client * num_clients * 10
        };

        for _i in 0..expected_lines {
            let (prev, matched) =
                proc.exp_regex(r#"init::fxmark: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
            *output += prev.as_str();
            *output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row = "git_rev,nclients,nreplicas,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched.split("init::fxmark: ").collect();
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = if !is_baseline {
                csv_file.write(format!("{},", num_clients).as_bytes())
            } else {
                csv_file.write(format!("{},", 0).as_bytes())
            };
            assert!(r.is_ok());
            let r = csv_file.write(format!("{},", num_clients).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());
        }
        Ok(())
    }

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.transport = transport;
    test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.clone();
    test.arg = Some(config);

    fn cmd_fn(num_cores: usize, arg: Option<FxmarkConfig>) -> String {
        // TODO: add in arg with formatting.
        //1XmixX0 is - mix benchmark for 0% writes with 1 open file
        let config = arg.expect("Missing fxmark config");
        format!(
            "initargs={}X{}XmixX{}",
            num_cores, config.open_files, config.write_ratio
        )
    }
    fn timeout_fn(num_cores: usize) -> u64 {
        180_000 + 5_000 * num_cores as u64
    }
    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            core::cmp::max(8192, 1024 * (((((num_cores + 1) / 2) + 3 - 1) / 3) * 3))
        }
    }
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn: timeout_fn,
        rackscale_timeout_fn: timeout_fn,
        mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, cfg!(feature = "smoke"));
    }
    bench.run_bench(false, cfg!(feature = "smoke"));
}

#[derive(Clone, Copy, PartialEq)]
enum VMOpsBench {
    MapLatency = 0,
    MapThroughput = 1,
    UnmapLatency = 2,
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_maptput_benchmark() {
    rackscale_vmops_benchmark(RackscaleTransport::Shmem, VMOpsBench::MapThroughput);
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_maplat_benchmark() {
    rackscale_vmops_benchmark(RackscaleTransport::Shmem, VMOpsBench::MapLatency);
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_unmaplat_benchmark() {
    rackscale_vmops_benchmark(RackscaleTransport::Shmem, VMOpsBench::UnmapLatency);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_vmops_benchmark(transport: RackscaleTransport, benchtype: VMOpsBench) {
    let testname_str = match benchtype {
        VMOpsBench::MapThroughput => "vmops",
        VMOpsBench::MapLatency => "vmops_latency",
        VMOpsBench::UnmapLatency => "vmops_unmaplat",
    };
    let file_name = format!(
        "rackscale_{}_{}_benchmark.csv",
        transport.to_string(),
        testname_str
    );
    let _ignore = std::fs::remove_file(file_name.clone());

    let mut build = BuildArgs::default().module("init").release();
    if benchtype == VMOpsBench::UnmapLatency {
        build = build.user_feature("bench-vmops-unmaplat");
    } else {
        build = build.user_feature("bench-vmops");
    }
    if benchtype == VMOpsBench::MapLatency || benchtype == VMOpsBench::UnmapLatency {
        build = build.user_feature("latency");
    }
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let built = build.build();

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        is_baseline: bool,
        arg: Option<VMOpsBench>,
    ) -> Result<()> {
        let benchtype = arg.expect("Expect a vmops type");
        let expected_lines = if cfg!(feature = "smoke") {
            1
        } else if benchtype == VMOpsBench::MapThroughput {
            cores_per_client * num_clients * 11
        } else {
            1
        };

        for _i in 0..expected_lines {
            let (prev, matched) = match benchtype {
                VMOpsBench::MapThroughput => proc.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                VMOpsBench::MapLatency => proc.exp_regex(r#"init::vmops: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                VMOpsBench::UnmapLatency => proc.exp_regex(r#"init::vmops::unmaplat: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
            };
            *output += prev.as_str();
            *output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row = match benchtype {
                    VMOpsBench::MapThroughput => "git_rev,nclients,nreplicas,thread_id,benchmark,ncores,memsize,duration_total,duration,operations\n",
                    _ => "git_rev,nclients,nreplicas,benchmark,ncores,memsize,p1,p25,p50,p75,p99,p999,p100\n",
                };
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = match benchtype {
                VMOpsBench::MapThroughput => matched.split("init::vmops: ").collect(),
                VMOpsBench::MapLatency => matched
                    .split("init::vmops: Latency percentiles: ")
                    .collect(),
                VMOpsBench::UnmapLatency => matched
                    .split("init::vmops::unmaplat: Latency percentiles: ")
                    .collect(),
            };

            assert!(parts.len() >= 2);
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = if !is_baseline {
                csv_file.write(format!("{},", num_clients).as_bytes())
            } else {
                csv_file.write(format!("{},", 0).as_bytes())
            };
            assert!(r.is_ok());
            let r = csv_file.write(format!("{},", num_clients).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());
        }
        Ok(())
    }

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.transport = transport;
    test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.clone();
    test.arg = Some(benchtype);

    fn cmd_fn(num_cores: usize, _arg: Option<VMOpsBench>) -> String {
        format!("initargs={}", num_cores)
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 500 * num_cores as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        240_000 + 1_000 * num_cores as u64
    }
    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            if num_cores < 48 {
                24 * 1024
            } else {
                48 * 1024
            }
        }
    }
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, cfg!(feature = "smoke"));
    }
    bench.run_bench(false, cfg!(feature = "smoke"));
}

#[derive(Clone)]
struct LevelDBConfig {
    reads: i32,
    num: i32,
    val_size: i32,
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_leveldb_benchmark() {
    // TODO(rackscale): because this test is flaky, always just run smoke test.
    // Seen bugs include mutex locking against itself, _lwp_exit returning after a thread has blocked.
    let is_smoke = true; // cfg!(feature = "smoke")

    let file_name = "rackscale_shmem_leveldb_benchmark.csv";
    let _ignore = std::fs::remove_file(file_name);

    let built = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:leveldb-bench")
        .release()
        .build();

    let config = if is_smoke {
        LevelDBConfig {
            reads: 10_000,
            num: 5_000,
            val_size: 4096,
        }
    } else {
        LevelDBConfig {
            reads: 100_000,
            num: 50_000,
            val_size: 65535,
        }
    };

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        is_baseline: bool,
        arg: Option<LevelDBConfig>,
    ) -> Result<()> {
        let config = arg.expect("match function expects a leveldb config");
        let (prev, matched) = proc.exp_regex(r#"readrandom(.*)"#)?;
        *output += prev.as_str();
        *output += matched.as_str();

        // Append parsed results to a CSV file
        let write_headers = !Path::new(file_name).exists();
        let mut csv_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Can't open file");
        if write_headers {
            let row = "git_rev,benchmark,nclients,nreplicas,ncores,reads,num,val_size,operations\n";
            let r = csv_file.write(row.as_bytes());
            assert!(r.is_ok());
        }

        let actual_num_clients = if is_baseline { 0 } else { num_clients };

        let parts: Vec<&str> = matched.split("ops/sec").collect();
        let mut parts: Vec<&str> = parts[0].split(" ").collect();
        parts.pop();
        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());
        let out = format!(
            "readrandom,{},{},{},{},{},{},{}",
            actual_num_clients,
            num_clients,
            cores_per_client * num_clients,
            config.reads,
            config.num,
            config.val_size,
            parts.last().unwrap()
        );
        let r = csv_file.write(out.as_bytes());
        assert!(r.is_ok());
        let r = csv_file.write("\n".as_bytes());
        assert!(r.is_ok());
        Ok(())
    }

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.transport = RackscaleTransport::Shmem;
    test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.to_string();
    test.arg = Some(config);
    test.run_dhcpd_for_baseline = true;

    fn cmd_fn(num_cores: usize, arg: Option<LevelDBConfig>) -> String {
        let config = arg.expect("missing leveldb config");
        format!(
            r#"init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
            num_cores, num_cores, config.reads, config.num, config.val_size
        )
    }

    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        40_000 + 500 * num_cores as u64
    }

    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        240_000 + 500 * num_cores as u64
    }

    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            core::cmp::max(8192, 1024 * (((((num_cores + 1) / 2) + 3 - 1) / 3) * 3))
        }
    }

    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, is_smoke);
    }
    bench.run_bench(false, is_smoke);
}

#[derive(Clone)]
struct MemcachedInternalConfig {
    pub num_queries: usize,
    pub mem_size: usize,
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_memcached_benchmark_internal() {
    rackscale_memcached_benchmark(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_memcached_benchmark(transport: RackscaleTransport) {
    let is_smoke = cfg!(feature = "smoke");

    let file_name = format!(
        "rackscale_{}_memcached_benchmark.csv",
        transport.to_string(),
    );
    let _ignore = std::fs::remove_file(file_name.clone());

    let built = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:memcached-bench")
        .kernel_feature("pages-4k")
        .release()
        .build();

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        is_baseline: bool,
        arg: Option<MemcachedInternalConfig>,
    ) -> Result<()> {
        let _config = arg.expect("match function expects a memcached config");

        // match the title
        let (prev, matched) = proc.exp_regex(r#"INTERNAL BENCHMARK CONFIGURE"#)?;

        *output += prev.as_str();
        *output += matched.as_str();

        // x_benchmark_mem = 10 MB
        let (prev, matched) = proc.exp_regex(r#"x_benchmark_mem = (\d+) MB"#)?;
        println!("> {}", matched);
        let b_mem = matched.replace("x_benchmark_mem = ", "").replace(" MB", "");

        *output += prev.as_str();
        *output += matched.as_str();

        // number of threads: 3
        let (prev, matched) = proc.exp_regex(r#"number of threads: (\d+)"#)?;
        println!("> {}", matched);
        let b_threads = matched.replace("number of threads: ", "");

        *output += prev.as_str();
        *output += matched.as_str();

        // number of keys: 131072
        let (prev, matched) = proc.exp_regex(r#"number of keys: (\d+)"#)?;
        println!("> {}", matched);

        *output += prev.as_str();
        *output += matched.as_str();

        let (prev, matched) = proc.exp_regex(r#"Executing (\d+) queries with (\d+) threads"#)?;
        println!("> {}", matched);

        *output += prev.as_str();
        *output += matched.as_str();

        // benchmark took 129 seconds
        let (prev, matched) = proc.exp_regex(r#"benchmark took (\d+) ms"#)?;
        println!("> {}", matched);
        let b_time = matched.replace("benchmark took ", "").replace(" ms", "");

        *output += prev.as_str();
        *output += matched.as_str();

        // benchmark took 7937984 queries / second
        let (prev, matched) = proc.exp_regex(r#"benchmark took (\d+) queries / second"#)?;
        println!("> {}", matched);
        let b_thpt = matched
            .replace("benchmark took ", "")
            .replace(" queries / second", "");

        *output += prev.as_str();
        *output += matched.as_str();

        let (prev, matched) = proc.exp_regex(r#"benchmark executed (\d+)"#)?;
        println!("> {}", matched);
        let b_queries = matched
            .replace("benchmark executed ", "")
            .split(" ")
            .next()
            .unwrap()
            .to_string();

        *output += prev.as_str();
        *output += matched.as_str();

        // Append parsed results to a CSV file
        let write_headers = !Path::new(file_name).exists();
        let mut csv_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Can't open file");
        if write_headers {
            let row = "git_rev,benchmark,nthreads,mem,queries,time,thpt,num_clients,num_replicas\n";
            let r = csv_file.write(row.as_bytes());
            assert!(r.is_ok());
        }

        let actual_num_clients = if is_baseline { 0 } else { num_clients };

        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());
        let out = format!(
            "memcached,{},{},{},{},{},{},{}",
            b_threads, b_mem, b_queries, b_time, b_thpt, actual_num_clients, num_clients
        );
        let r = csv_file.write(out.as_bytes());
        assert!(r.is_ok());
        let r = csv_file.write("\n".as_bytes());
        assert!(r.is_ok());

        Ok(())
    }

    let config = if is_smoke {
        MemcachedInternalConfig {
            num_queries: 100_000,
            mem_size: 16,
        }
    } else {
        MemcachedInternalConfig {
            num_queries: 1_000_000, // TODO(rackscale): should be 100_000_000,
            mem_size: 16,           // TODO(rackscale): should be 32_000,
        }
    };

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.transport = transport;
    //test.shmem_size = 1024 * 64; // this works just fine
    test.shmem_size *= 2;
    test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.to_string();
    test.arg = Some(config);
    test.run_dhcpd_for_baseline = true;

    fn cmd_fn(num_cores: usize, arg: Option<MemcachedInternalConfig>) -> String {
        let config = arg.expect("missing leveldb config");
        format!(
            r#"init=memcachedbench.bin initargs={} appcmd='--x-benchmark-mem={} --x-benchmark-queries={}'"#,
            num_cores, config.mem_size, config.num_queries
        )
    }

    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        240_000 + 1_000 * num_cores as u64
    }

    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        600_000 + 6_000 * num_cores as u64
    }

    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            core::cmp::max(8192, 1024 * (((((num_cores + 1) / 2) + 3 - 1) / 3) * 3))
        }
    }

    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, is_smoke);
    }
    bench.run_bench(false, is_smoke);
}

#[ignore]
#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_dcmconfig_benchmark() {
    let file_name = "rackscale_dcmconfig_benchmark.csv";
    let _ignore = std::fs::remove_file(file_name.clone());
    let mut csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let row = "git_rev,benchmark,nthreads,mem,queries,time,thpt,num_clients,num_replicas,solver\n";
    let r = csv_file.write(row.as_bytes());
    assert!(r.is_ok());

    let mut dcm_config = DCMConfig::default();

    dcm_config.solver = DCMSolver::DCMloc;
    rackscale_memcached_dcm(RackscaleTransport::Shmem, Some(dcm_config.clone()));

    dcm_config.solver = DCMSolver::DCMcap;
    rackscale_memcached_dcm(RackscaleTransport::Shmem, Some(dcm_config.clone()));

    dcm_config.solver = DCMSolver::Random;
    rackscale_memcached_dcm(RackscaleTransport::Shmem, Some(dcm_config.clone()));

    dcm_config.solver = DCMSolver::RoundRobin;
    rackscale_memcached_dcm(RackscaleTransport::Shmem, Some(dcm_config.clone()));

    dcm_config.solver = DCMSolver::FillCurrent;
    rackscale_memcached_dcm(RackscaleTransport::Shmem, Some(dcm_config.clone()));

    let solvers = vec!["DCMloc", "DCMcap", "Random", "RoundRobin", "FillCurrent"];

    for solver in solvers {
        let data = std::fs::read_to_string(format!("/tmp/dcm_{}.csv", solver))
            .expect("Cannot open dcm benchmark file");
        // Ignore csv header
        let lines: Vec<&str> = data.lines().collect();
        for i in 1..lines.len() {
            let r = csv_file.write(format!("{},{}\n", lines[i], solver).as_bytes());
            assert!(r.is_ok());
        }
        let _ignore = std::fs::remove_file(format!("/tmp/dcm_{}.csv", solver));
    }
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_memcached_dcm(transport: RackscaleTransport, dcm_config: Option<DCMConfig>) {
    let is_smoke = cfg!(feature = "smoke");

    let file_name = match dcm_config {
        Some(config) => match config.solver {
            DCMSolver::DCMloc => "/tmp/dcm_DCMloc.csv".to_string(),
            DCMSolver::DCMcap => "/tmp/dcm_DCMcap.csv".to_string(),
            DCMSolver::Random => "/tmp/dcm_Random.csv".to_string(),
            DCMSolver::RoundRobin => "/tmp/dcm_RoundRobin.csv".to_string(),
            DCMSolver::FillCurrent => "/tmp/dcm_FillCurrent.csv".to_string(),
        },
        None => format!(
            "rackscale_{}_memcached_benchmark.csv",
            transport.to_string(),
        ),
    };

    let _ignore = std::fs::remove_file(file_name.clone());

    let iterations = if dcm_config.is_some() { 2 } else { 1 };

    for _ in 0..iterations {
        let built = BuildArgs::default()
            .module("rkapps")
            .user_feature("rkapps:memcached-bench")
            .kernel_feature("pages-4k")
            .release()
            .set_rackscale(true)
            .build();

        fn controller_match_fn(
            proc: &mut PtySession,
            output: &mut String,
            _cores_per_client: usize,
            num_clients: usize,
            file_name: &str,
            is_baseline: bool,
            arg: Option<MemcachedInternalConfig>,
        ) -> Result<()> {
            let _config = arg.expect("match function expects a memcached config");

            // match the title
            let (prev, matched) = proc.exp_regex(r#"INTERNAL BENCHMARK CONFIGURE"#)?;

            *output += prev.as_str();
            *output += matched.as_str();

            // x_benchmark_mem = 10 MB
            let (prev, matched) = proc.exp_regex(r#"x_benchmark_mem = (\d+) MB"#)?;
            println!("> {}", matched);
            let b_mem = matched.replace("x_benchmark_mem = ", "").replace(" MB", "");

            *output += prev.as_str();
            *output += matched.as_str();

            // number of threads: 3
            let (prev, matched) = proc.exp_regex(r#"number of threads: (\d+)"#)?;
            println!("> {}", matched);
            let b_threads = matched.replace("number of threads: ", "");

            *output += prev.as_str();
            *output += matched.as_str();

            // number of keys: 131072
            let (prev, matched) = proc.exp_regex(r#"number of keys: (\d+)"#)?;
            println!("> {}", matched);

            *output += prev.as_str();
            *output += matched.as_str();

            let (prev, matched) =
                proc.exp_regex(r#"Executing (\d+) queries with (\d+) threads"#)?;
            println!("> {}", matched);

            *output += prev.as_str();
            *output += matched.as_str();

            // benchmark took 129 seconds
            let (prev, matched) = proc.exp_regex(r#"benchmark took (\d+) ms"#)?;
            println!("> {}", matched);
            let b_time = matched.replace("benchmark took ", "").replace(" ms", "");

            *output += prev.as_str();
            *output += matched.as_str();

            // benchmark took 7937984 queries / second
            let (prev, matched) = proc.exp_regex(r#"benchmark took (\d+) queries / second"#)?;
            println!("> {}", matched);
            let b_thpt = matched
                .replace("benchmark took ", "")
                .replace(" queries / second", "");

            *output += prev.as_str();
            *output += matched.as_str();

            let (prev, matched) = proc.exp_regex(r#"benchmark executed (\d+)"#)?;
            println!("> {}", matched);
            let b_queries = matched
                .replace("benchmark executed ", "")
                .split(" ")
                .next()
                .unwrap()
                .to_string();

            *output += prev.as_str();
            *output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row =
                    "git_rev,benchmark,nthreads,mem,queries,time,thpt,num_clients,num_replicas\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let actual_num_clients = if is_baseline { 0 } else { num_clients };

            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let out = format!(
                "memcached,{},{},{},{},{},{},{}",
                b_threads, b_mem, b_queries, b_time, b_thpt, actual_num_clients, num_clients
            );
            let r = csv_file.write(out.as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            Ok(())
        }

        let config = if is_smoke {
            MemcachedInternalConfig {
                num_queries: 100_000,
                mem_size: 16,
            }
        } else {
            MemcachedInternalConfig {
                num_queries: 1_000_000, // TODO(rackscale): should be 100_000_000,
                mem_size: 16,           // TODO(rackscale): should be 32_000,
            }
        };

        let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
        test.controller_match_fn = controller_match_fn;
        test.transport = transport;
        test.shmem_size *= 2;
        test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
        test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
        test.file_name = file_name.to_string();
        test.arg = Some(config);
        test.run_dhcpd_for_baseline = true;

        test.dcm_config = Some(dcm_config.unwrap());

        let machine = Machine::determine();
        let max_cores = machine.max_cores();
        let max_numa_nodes = machine.max_numa_nodes();

        let cores_per_client = max_cores / max_numa_nodes;
        test.num_clients = max_numa_nodes - 1;
        test.cores_per_client = cores_per_client;
        test.memory = 2048 * (((((cores_per_client + 1) / 2) + 3 - 1) / 3) * 3);
        test.cmd = format!("init=memcachedbench.bin initargs={} appcmd='--x-benchmark-mem=16 --x-benchmark-queries=1000000'", cores_per_client);
        test.client_timeout = 120_000;
        test.controller_timeout = 120_000;
        test.run_rackscale();
    }
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_monetdb_benchmark() {
    rackscale_monetdb_benchmark(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_monetdb_benchmark(transport: RackscaleTransport) {
    // TODO(rackscale): test under development, should not always be smoke permanently
    let is_smoke = true; // cfg!(feature = "smoke")

    let file_name = format!("rackscale_{}_monetdb_benchmark.csv", transport.to_string(),);
    let _ignore = std::fs::remove_file(file_name.clone());

    let built = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:monetdb")
        .release()
        .build();

    fn controller_match_fn(
        proc: &mut PtySession,
        _output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
        _file_name: &str,
        _is_baseline: bool,
        _arg: Option<()>,
    ) -> Result<()> {
        // TODO: currently we don't have anything running here
        let (prev, matched) = proc.exp_regex(r#"monetdbd:"#)?;
        println!("{prev}");
        println!("> {}", matched);

        Ok(())
    }

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.transport = transport;
    test.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.to_string();
    test.arg = None;
    test.run_dhcpd_for_baseline = true;

    fn cmd_fn(num_cores: usize, _arg: Option<()>) -> String {
        format!(
            r#"init=monetdbd.bin initargs={} appcmd='create dbfarm'"#,
            num_cores
        )
    }

    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 500 * num_cores as u64
    }

    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        180_000 + 500 * num_cores as u64
    }

    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            core::cmp::max(8192, 1024 * (((((num_cores + 1) / 2) + 3 - 1) / 3) * 3))
        }
    }

    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, is_smoke);
    }
    bench.run_bench(false, is_smoke);
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_memhash_benchmark() {
    rackscale_memhash_benchmark(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_memhash_benchmark(transport: RackscaleTransport) {
    let machine = Machine::determine();
    let max_cores = machine.max_cores();
    let max_numa_nodes = machine.max_numa_nodes();
    println!(
        "\nMax cores: {:?}, Max numa nodes: {:?}",
        max_cores, max_numa_nodes
    );

    let file_name = format!("rackscale_{}_memhash_benchmark.csv", transport.to_string());
    let _ignore = std::fs::remove_file(file_name.clone());

    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("memhash")
        .set_rackscale(true)
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let built = build.build();

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        _is_baseline: bool,
        _arg: Option<()>,
    ) -> Result<()> {
        let expected_lines = if cfg!(feature = "smoke") {
            1
        } else {
            let tot_cores = cores_per_client * num_clients;
            ((tot_cores * (tot_cores + 1)) / 2) * 2 - tot_cores // account for decrementing cores
        };

        for _i in 0..expected_lines {
            let (prev, matched) =
                proc.exp_regex(r#"init::memhash: (\d+),(.*),(\d+),(\d+),(\d+),(\d+)"#)?;
            *output += prev.as_str();
            *output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row = "git_rev,nclients,cores_per_client,thread_id,benchmark,operations,ncores,tot_cores,time\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched.split("init::memhash: ").collect();
            assert!(parts.len() >= 2);

            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());

            let r = csv_file.write(format!("{},", num_clients).as_bytes());
            assert!(r.is_ok());

            let r = csv_file.write(format!("{},", cores_per_client).as_bytes());
            assert!(r.is_ok());

            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());
        }
        Ok(())
    }

    let mut test_run = RackscaleRun::new("userspace-smp".to_string(), built);
    test_run.controller_match_fn = controller_match_fn;
    test_run.transport = transport;
    test_run.use_affinity_shmem = cfg!(feature = "affinity-shmem");
    test_run.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test_run.file_name = file_name.clone();
    test_run.num_clients = max_numa_nodes - 1; // Reserve node for controller
    test_run.cores_per_client = max_cores / max_numa_nodes; // May actually be max_cores / num_hwthread_per_cpu
    test_run.client_timeout = 240_000;
    test_run.controller_timeout = 240_000;
    test_run.shmem_size *= 4;
    test_run.run_rackscale();
}
