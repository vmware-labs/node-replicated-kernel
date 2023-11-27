// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s11_*`: Rackscale (distributed) benchmarks
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rexpect::errors::*;
use rexpect::session::spawn_command;
use rexpect::session::PtySession;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{DCMConfig, DCMSolver};

use testutils::rackscale_runner::{RackscaleBench, RackscaleRun};
use testutils::runner_args::RackscaleTransport;

use testutils::memcached::{
    linux_spawn_memcached, parse_memcached_output, rackscale_memcached_checkout,
    MemcachedShardedConfig, MEMCACHED_MEM_SIZE_MB, MEMCACHED_NUM_QUERIES,
    RACKSCALE_MEMCACHED_CSV_COLUMNS,
};

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

    fn cmd_fn(num_cores: usize, _num_clients: usize, arg: Option<FxmarkConfig>) -> String {
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
    fn mem_fn(num_cores: usize, _num_clients: usize, is_smoke: bool) -> usize {
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

    fn cmd_fn(num_cores: usize, _num_clients: usize, _arg: Option<VMOpsBench>) -> String {
        format!("initargs={}", num_cores)
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 500 * num_cores as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        240_000 + 1_000 * num_cores as u64
    }
    fn mem_fn(num_cores: usize, _num_clients: usize, is_smoke: bool) -> usize {
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

    fn cmd_fn(num_cores: usize, _num_clients: usize, arg: Option<LevelDBConfig>) -> String {
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

    fn mem_fn(num_cores: usize, _num_clients: usize, is_smoke: bool) -> usize {
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
fn s11_rackscale_shmem_memcached_internal_benchmark() {
    rackscale_memcached_internal_benchmark(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_memcached_internal_benchmark(transport: RackscaleTransport) {
    let is_smoke = cfg!(feature = "smoke");

    let file_name = format!(
        "rackscale_{}_memcached_benchmark.csv",
        transport.to_string(),
    );
    let _ignore = std::fs::remove_file(file_name.clone());

    let baseline_file_name = "rackscale_baseline_memcached_benchmark.csv";
    if cfg!(feature = "baseline") {
        let _ignore = std::fs::remove_file(baseline_file_name.clone());
    }

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

        let ret = parse_memcached_output(proc, output)?;

        // Append parsed results to a CSV file
        let write_headers = !Path::new(file_name).exists();
        let mut csv_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Can't open file");
        if write_headers {
            let r = csv_file.write(RACKSCALE_MEMCACHED_CSV_COLUMNS.as_bytes());
            assert!(r.is_ok());
        }

        let os_name = if is_baseline { "nros" } else { "dinos" };
        let protocol = if is_baseline {
            "internal"
        } else if file_name.contains(&RackscaleTransport::Ethernet.to_string()) {
            "tcp"
        } else {
            "shmem"
        };

        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());

        let out = format!(
            "memcached_internal,{},{},{},{},{},{},{},{}",
            os_name,
            protocol,
            num_clients,
            ret.b_threads,
            ret.b_mem,
            ret.b_queries,
            ret.b_time,
            ret.b_thpt
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
        // keep in sync with the s10_memcached_benchmark_internal configuration
        // and the s11_rackscale_memcached_benchmark_sharded configuration
        MemcachedInternalConfig {
            num_queries: MEMCACHED_NUM_QUERIES,
            mem_size: MEMCACHED_MEM_SIZE_MB,
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

    if !is_smoke {
        test.shmem_size = std::cmp::max(
            MEMCACHED_MEM_SIZE_MB * 2,
            testutils::helpers::SHMEM_SIZE * 2,
        );
    }

    fn cmd_fn(
        num_cores: usize,
        _num_clients: usize,
        arg: Option<MemcachedInternalConfig>,
    ) -> String {
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
        if cfg!(feature = "smoke") {
            60_000 as u64
        } else {
            (MEMCACHED_MEM_SIZE_MB / 10 * 1000 + MEMCACHED_NUM_QUERIES) as u64
        }
    }

    fn mem_fn(num_cores: usize, num_clients: usize, is_smoke: bool) -> usize {
        let base_memory = if num_cores > 64 { 8192 } else { 4096 };

        if is_smoke {
            base_memory
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            // memory = result of this function / num_clients  - shmem_size
            (base_memory
                + std::cmp::max(
                    MEMCACHED_MEM_SIZE_MB * 2,
                    testutils::helpers::SHMEM_SIZE * 2,
                ))
                * num_clients
        }
    }

    let mut bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };

    bench.run_bench(false, is_smoke);

    if cfg!(feature = "baseline") {
        bench.test.file_name = baseline_file_name.to_string();
        bench.run_bench(true, is_smoke);
    }
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
fn s11_linux_memcached_sharded_benchmark() {
    use rexpect::process::signal::Signal::SIGKILL;

    let machine = Machine::determine();
    let out_dir_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sharded-memcached");
    let is_smoke = cfg!(feature = "smoke");

    rackscale_memcached_checkout(env!("CARGO_TARGET_TMPDIR"));

    // stuff has been built, now we can run the benchmark
    let mut config = if is_smoke {
        MemcachedShardedConfig {
            num_servers: 1,
            num_queries: 100_000,
            mem_size: 16,
            protocol: "tcp",
            is_local_host: true,
            num_threads: 8,
            path: out_dir_path,
        }
    } else {
        // keep in sync with the s10_memcached_benchmark_internal configuration
        MemcachedShardedConfig {
            num_servers: 1,
            num_queries: MEMCACHED_NUM_QUERIES,
            mem_size: MEMCACHED_MEM_SIZE_MB,
            protocol: "tcp",
            is_local_host: true,
            num_threads: 8,
            path: out_dir_path,
        }
    };

    let timeout_ms = if is_smoke { 60_000 } else { std::cmp::max(config.mem_size / 10 * 1000, 60_000) + std::cmp::max(60_000, config.num_queries / 1000) } as u64;

    fn run_benchmark_internal(config: &MemcachedShardedConfig, timeout_ms: u64) -> PtySession {
        Command::new("killall").args(&["memcached"]).status().ok();

        let mut command = Command::new("taskset");
        command.arg("--cpu-list");
        command.arg(format!("0-{}", config.num_threads - 1).as_str());
        command.arg("./build/bin/memcached");
        command.arg(format!("--x-benchmark-queries={}", config.num_queries).as_str());
        command.arg(format!("--x-benchmark-mem={}", config.mem_size).as_str());
        command.current_dir(config.path.as_path());
        spawn_command(command, Some(timeout_ms)).expect("failed to spawn memcached")
    }

    let file_name = "linux_memcached_sharded_benchmark.csv";

    let _r = std::fs::remove_file(file_name);

    let mut csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let r = csv_file.write(RACKSCALE_MEMCACHED_CSV_COLUMNS.as_bytes());
    assert!(r.is_ok());

    let machine = Machine::determine();
    let max_cores = if is_smoke { 2 } else { machine.max_cores() };
    let max_numa = machine.max_numa_nodes();
    let total_cores_per_node = core::cmp::max(1, max_cores / max_numa);

    // Do initial network configuration
    let mut num_clients = 1; // num_clients == num_replicas, for baseline
    let mut total_cores = 1;
    while total_cores < max_cores {
        // Round up to get the number of clients
        let new_num_clients = (total_cores + (total_cores_per_node - 1)) / total_cores_per_node;

        // Do network setup if number of clients has changed.
        if num_clients != new_num_clients {
            num_clients = new_num_clients;

            // ensure total cores is divisible by num clients
            total_cores = total_cores - (total_cores % num_clients);
        }
        let cores_per_client = total_cores / num_clients;

        // Break if not enough total cores for the controller, or if we would have to split controller across nodes to make it fit
        // We want controller to have it's own socket, so if it's not a 1 socket machine, break when there's equal number of clients
        // to numa nodes.
        if total_cores + num_clients + 1 > machine.max_cores()
            || num_clients == machine.max_numa_nodes()
                && cores_per_client + num_clients + 1 > total_cores_per_node
            || num_clients == max_numa && max_numa > 1
        {
            break;
        }

        eprintln!(
                "\n\nRunning Sharded Memcached test with {:?} total core(s), {:?} (client|replica)(s) (cores_per_(client|replica)={:?})",
                total_cores, num_clients, cores_per_client
            );

        // terminate any previous memcached
        let _ = Command::new("killall")
            .args(&["memcached", "-s", "SIGKILL"])
            .output();

        // run the internal configuration
        config.num_threads = total_cores;

        println!("Memcached Internal: {total_cores} cores");

        let mut pty = run_benchmark_internal(&config, timeout_ms);
        let mut output = String::new();
        let res = parse_memcached_output(&mut pty, &mut output).expect("could not parse output!");
        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());
        let out = format!(
            "memcached_sharded,linux,{},{},{},{},{},{}\n",
            res.b_threads, "internal", res.b_mem, res.b_queries, res.b_time, res.b_thpt,
        );
        let r = csv_file.write(out.as_bytes());
        assert!(r.is_ok());

        let r = pty
            .process
            .kill(SIGKILL)
            .expect("unable to terminate memcached");

        for protocol in &["tcp", "unix"] {
            config.protocol = protocol;
            config.num_servers = num_clients;
            config.num_threads = cores_per_client;

            println!("Memcached Sharded: {cores_per_client}x{num_clients} with {protocol}");

            // terminate the memcached instance
            let _ = Command::new("killall")
                .args(&["memcached", "-s", "SIGKILL"])
                .status();

            // give some time so memcached can be cleaned up
            std::thread::sleep(Duration::from_secs(5));

            let mut memcached_ctrls = Vec::new();
            for i in 0..num_clients {
                memcached_ctrls.push(
                    linux_spawn_memcached(i, &config, timeout_ms)
                        .expect("could not spawn memcached"),
                );
            }

            config.num_threads = total_cores;

            let mut pty = testutils::memcached::spawn_loadbalancer(&config, timeout_ms)
                .expect("failed to spawn load balancer");
            let mut output = String::new();
            use rexpect::errors::ErrorKind::Timeout;
            match parse_memcached_output(&mut pty, &mut output) {
                Ok(res) => {
                    let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                    assert!(r.is_ok());
                    let out = format!(
                        "memcached_sharded,linux,{},{},{},{},{},{}\n",
                        res.b_threads, protocol, res.b_mem, res.b_queries, res.b_time, res.b_thpt,
                    );
                    let r = csv_file.write(out.as_bytes());
                    assert!(r.is_ok());

                    println!("{:?}", res);
                }
                Err(e) => {
                    if let Timeout(expected, got, timeout) = e.0 {
                        println!("Timeout while waiting for {} ms\n", timeout.as_millis());
                        println!("Expected: `{expected}`\n");
                        println!("Got:",);
                        for l in got.lines().take(5) {
                            println!(" > {l}");
                        }
                    } else {
                        println!("error: {}", e);
                    }

                    let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                    assert!(r.is_ok());
                    let out = format!(
                        "memcached_sharded,linux,{},{},failure,failure,failure,failure\n",
                        config.num_servers, protocol,
                    );
                    let r = csv_file.write(out.as_bytes());
                    assert!(r.is_ok());

                    for mc in memcached_ctrls.iter_mut() {
                        mc.process
                            .kill(rexpect::process::signal::Signal::SIGKILL)
                            .expect("couldn't terminate memcached");
                        while let Ok(l) = mc.read_line() {
                            println!("MEMCACHED-OUTPUT: {}", l);
                        }
                    }
                }
            };

            if total_cores == 1 {
                total_cores = 0;
            }

            if num_clients == 3 {
                total_cores += 3;
            } else {
                total_cores += 4;
            }

            let _ = pty.process.kill(rexpect::process::signal::Signal::SIGKILL);
        }
    }

    // terminate the memcached instance
    let _ = Command::new("killall")
        .args(&["memcached", "-s", "SIGKILL"])
        .status();
}

#[test]
#[ignore]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_memcached_benchmark_sharded_nros() {
    use rexpect::process::signal::Signal::SIGKILL;

    let out_dir_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sharded-memcached");
    let is_smoke = cfg!(feature = "smoke");

    rackscale_memcached_checkout(env!("CARGO_TARGET_TMPDIR"));

    // stuff has been built, now we can run the benchmark
    let mut config = if is_smoke {
        MemcachedShardedConfig {
            num_servers: 1,
            num_queries: 100_000,
            mem_size: 16,
            protocol: "tcp",
            is_local_host: true,
            num_threads: 4,
            path: out_dir_path,
        }
    } else {
        // keep in sync with the s10_memcached_benchmark_internal configuration
        MemcachedShardedConfig {
            num_servers: 1,
            num_queries: MEMCACHED_NUM_QUERIES,
            mem_size: MEMCACHED_MEM_SIZE_MB,
            protocol: "tcp",
            is_local_host: true,
            num_threads: 4,
            path: out_dir_path,
        }
    };

    // TODO: consolidate code with testutils::memcached::spawn_loadbalancer
    fn spawn_loadbalancer(config: &MemcachedShardedConfig, timeout_ms: u64) -> Result<PtySession> {
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
                    servers.push_str(format!("tcp://localhost:{}", 11211 + i).as_str());
                } else {
                    // +1 because tap0 is reserved for the controller.
                    let ip = 10 + i + 1;
                    servers.push_str(format!("tcp://172.31.0.{}:{}", ip, 11211).as_str());
                }
            } else {
                servers.push_str(
                    format!("unix://{}/memcached{}.sock", config.path.display(), i).as_str(),
                );
            }
        }
        command.arg(servers.as_str());
        command.current_dir(config.path.as_path());

        // give the servers some time to be spawned
        std::thread::sleep(Duration::from_secs(5));

        println!("Spawning Loadbalancer: \n $ `{:?}`", command);

        spawn_command(command, Some(timeout_ms))
    }

    let file_name = "memcached_benchmark_sharded_nros.csv";
    let _r = std::fs::remove_file(file_name);

    let mut csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let row = "git_rev,benchmark,os,nthreads,protocol,mem,queries,time,thpt\n";
    let r = csv_file.write(row.as_bytes());
    assert!(r.is_ok());

    // run with NrOS as host
    let built = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:memcached-bench")
        .user_feature("rkapps:virtio")
        .user_feature("libvibrio:virtio")
        .kernel_feature("pages-4k")
        .release()
        .set_rackscale(false)
        .build();

    fn controller_run_fun(
        config: Option<&MemcachedShardedConfig>,
        num_servers: usize,
        num_threads: usize,
        timeout_ms: u64,
    ) -> Result<PtySession> {
        // here we should wait
        std::thread::sleep(Duration::from_secs(15 + 2 * num_servers as u64));

        let mut config = config.unwrap().clone();

        config.num_servers = num_servers;
        config.num_threads = num_servers * num_threads;
        spawn_loadbalancer(&config, timeout_ms)
    }

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
        file_name: &str,
        _is_baseline: bool,
        _arg: Option<MemcachedShardedConfig>,
    ) -> Result<()> {
        let mut csv_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Can't open file");

        use rexpect::errors::Error;
        use rexpect::errors::ErrorKind::Timeout;
        let res = match parse_memcached_output(proc, output) {
            Ok(res) => res,
            Err(Error(Timeout(expected, got, timeout), st)) => {
                println!("Expected: `{expected}`\n");
                println!("Got:",);
                for l in got.lines().take(5) {
                    println!(" > {l}");
                }
                return Err(Error(Timeout(expected, got, timeout), st));
            }
            Err(err) => {
                // println!("Failed: {:?}", err);
                return Err(err);
            }
        };

        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());
        let out = format!(
            "memcached_sharded,nros,{},{},{},{},{},{}\n",
            res.b_threads, "tcp", res.b_mem, res.b_queries, res.b_time, res.b_thpt,
        );
        let r = csv_file.write(out.as_bytes());
        assert!(r.is_ok());

        Ok(())
    }

    fn client_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
        _file_name: &str,
        _is_baseline: bool,
        _arg: Option<MemcachedShardedConfig>,
    ) -> Result<()> {
        match proc.exp_regex(r#"dhcp: vioif0: adding IP address (\d+).(\d+).(\d+).(\d+)/(\d+)"#) {
            Ok((_prev, matched)) => {
                println!(" > Networking setup succeeded. {matched}");
            }
            Err(e) => {
                println!(" > Networking setup failed. {e}");
                return Err(e);
            }
        }

        match proc.exp_regex(r#"INTERNAL BENCHMARK CONFIGURE"#) {
            Ok((prev, matched)) => {
                println!(" > Memcached started.");
                *output += prev.as_str();
                *output += matched.as_str();
            }
            Err(e) => {
                println!(" > Memcached failed to start. {e}");
                return Err(e);
            }
        }

        let (prev, matched) = proc.exp_regex(r#"x_benchmark_mem = (\d+) MB"#).unwrap();
        println!("> {}", matched);
        // let b_mem = matched.replace("x_benchmark_mem = ", "").replace(" MB", "");

        *output += prev.as_str();
        *output += matched.as_str();
        Ok(())
    }

    config.is_local_host = false;
    config.protocol = "tcp";

    let mut test = RackscaleRun::new("userspace-smp".to_string(), built);
    test.controller_match_fn = controller_match_fn;
    test.controller_run_fn = Some(controller_run_fun);
    test.client_match_fn = client_match_fn;
    test.use_qemu_huge_pages = cfg!(feature = "affinity-shmem");
    test.file_name = file_name.to_string();
    test.arg = Some(config);
    test.run_dhcpd_for_baseline = true;
    test.is_multi_node = true;
    test.shmem_size = 0;

    fn cmd_fn(num_cores: usize, num_clients: usize, arg: Option<MemcachedShardedConfig>) -> String {
        let config = arg.expect("missing configuration");
        let num_threads = num_cores / num_clients;

        format!(
            r#"init=memcachedbench.bin initargs={num_threads} appcmd='--x-benchmark-no-run --disable-evictions --conn-limit=1024 --threads={num_threads} --x-benchmark-mem={} --memory-limit={}'"#,
            config.mem_size * 2,
            config.mem_size * 4
        )
    }

    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 500 * num_cores as u64
    }

    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        1200_000 + 60_000 * num_cores as u64
    }

    fn mem_fn(_num_cores: usize, num_clients: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            // Memory must also be divisible by number of nodes, which could be 1, 2, 3, or 4
            // mem = result of this function / num_clients - shmem_size
            (8092
                + 2 * std::cmp::max(
                    MEMCACHED_MEM_SIZE_MB * 2,
                    testutils::helpers::SHMEM_SIZE * 2,
                ))
                * num_clients
        }
    }

    println!("----------------------------------------------------------");

    let machine = Machine::determine();

    let mut pings = Vec::new();
    for i in 0..machine.max_numa_nodes() {
        let mut command = Command::new("ping");
        command.arg(&format!("172.31.0.{}", 10 + i + 1));

        let proc = spawn_command(command, None).unwrap();
        pings.push(proc);
    }

    // construct bench and run it!
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        mem_fn,
    };
    bench.run_bench(false, is_smoke);
    for mut ping in pings.into_iter() {
        if !ping.process.kill(SIGKILL).is_ok() {
            println!("Failed to kill ping process");
        }
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

    fn cmd_fn(num_cores: usize, _num_clients: usize, _arg: Option<()>) -> String {
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

    fn mem_fn(num_cores: usize, _num_clients: usize, is_smoke: bool) -> usize {
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
