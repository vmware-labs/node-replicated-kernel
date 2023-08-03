// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s10_*`: User-space applications benchmarks

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use csv::WriterBuilder;
use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::spawn;
use serde::Serialize;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{setup_network, spawn_dhcpd, spawn_nrk, DHCP_ACK_MATCH};
use testutils::redis::{redis_benchmark, REDIS_BENCHMARK, REDIS_START_MATCH};
use testutils::runner_args::{check_for_successful_exit, wait_for_sigterm, RunnerArgs};

/// Binary of the memcached benchmark program
const MEMASLAP_BINARY: &str = "memaslap";

#[cfg(not(feature = "baremetal"))]
#[test]
fn s10_redis_benchmark_virtio() {
    let _r = which::which(REDIS_BENCHMARK)
        .expect("redis-benchmark not installed on host, test will fail!");

    setup_network(1);

    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:redis")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build)
        .cmd("init=redis.bin")
        .use_virtio()
        .timeout(45_000)
        .no_network_setup();

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut p = spawn_nrk(&cmdline)?;

        // Test that DHCP works:
        output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();
        output += p.exp_string(REDIS_START_MATCH)?.as_str();

        std::thread::sleep(std::time::Duration::from_secs(9));

        let mut redis_client = redis_benchmark("virtio", 2_000_000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s10_redis_benchmark_e1000() {
    setup_network(1);

    let _r = which::which(REDIS_BENCHMARK)
        .expect("redis-benchmark not installed on host, test will fail!");

    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:redis")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build)
        .cmd("init=redis.bin")
        .timeout(45_000)
        .no_network_setup();

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut p = spawn_nrk(&cmdline)?;

        // Test that DHCP works:
        dhcp_server.exp_regex(DHCP_ACK_MATCH)?;
        output += p.exp_string(REDIS_START_MATCH)?.as_str();

        use std::{thread, time};
        thread::sleep(time::Duration::from_secs(9));

        let mut redis_client = redis_benchmark("e1000", 2_000_000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

#[test]
fn s10_vmops_benchmark() {
    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("bench-vmops")
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let build = build.build();
    let machine = Machine::determine();
    let threads = machine.thread_defaults_uniform();

    let file_name = "vmops_benchmark.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
            .cores(machine.max_cores())
            .setaffinity(Vec::new())
            .timeout(12_000 + cores as u64 * 3000)
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(16 * 1024);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like
            // `init::vmops: 1,maponly,1,4096,10000,1000,634948`
            // write them to a CSV file
            let expected_lines = if cfg!(feature = "smoke") {
                1
            } else {
                with_cores * 11
            };

            for _i in 0..expected_lines {
                let (prev, matched) =
                    p.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
                output += prev.as_str();
                output += matched.as_str();

                // Append parsed results to a CSV file
                let write_headers = !Path::new(file_name).exists();
                let mut csv_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(file_name)
                    .expect("Can't open file");
                if write_headers {
                    let row =
                        "git_rev,thread_id,benchmark,ncores,memsize,duration_total,duration,operations\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let parts: Vec<&str> = matched.split("init::vmops: ").collect();
                let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write(parts[1].as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write("\n".as_bytes());
                assert!(r.is_ok());
            }

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s10_shootdown_simple() {
    let machine = Machine::determine();
    let build = BuildArgs::default().module("init").release();
    let build = if cfg!(feature = "smoke") {
        build.user_feature("smoke").build()
    } else {
        build.build()
    };

    let threads = machine.thread_defaults_uniform();

    let file_name = "tlb_shootdown.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new_with_build("shootdown-simple", &build)
            .cores(cores)
            .setaffinity(Vec::new())
            .timeout(12_000 + cores as u64 * 3000)
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(8192);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        let num_nodes = if cfg!(feature = "smoke") && cores > 2 {
            core::cmp::min(cores, 2)
        } else {
            let max_numa_nodes = cmdline.machine.max_numa_nodes();
            core::cmp::min(cores, max_numa_nodes)
        };
        cmdline = cmdline.nodes(num_nodes);

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like
            // `init::vmops: 1,maponly,1,4096,10000,1000,634948`
            // write them to a CSV file
            let expected_lines = 1;
            for _i in 0..expected_lines {
                let (prev, matched) = p.exp_regex(r#"shootdown-simple,(\d+),(\d+)"#)?;
                output += prev.as_str();
                output += matched.as_str();

                // Append parsed results to a CSV file
                let write_headers = !Path::new(file_name).exists();
                let mut csv_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(file_name)
                    .expect("Can't open file");
                if write_headers {
                    let row = "git_rev,name,cores,shootdown_duration_ns\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write(matched.as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write("\n".as_bytes());
                assert!(r.is_ok());
            }

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(), output);
    }
}

#[test]
fn s10_vmops_latency_benchmark() {
    let machine = Machine::determine();
    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("bench-vmops")
        .user_feature("latency")
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let build = build.build();

    let threads = machine.thread_defaults_uniform();

    let file_name = "vmops_benchmark_latency.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
            .cores(machine.max_cores())
            .setaffinity(Vec::new())
            .timeout(25_000 + cores as u64 * 100_000)
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(24 * 1024);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like:
            // "Latency percentiles [ns]: maponly,2,4096,1092,1351,1939,3111,4711,9864,2089812"
            // and writes them to a CSV file
            let (prev, matched) =
                    p.exp_regex(r#"init::vmops: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
            output += prev.as_str();
            output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");

            if write_headers {
                let row = "git_rev,benchmark,ncores,memsize,p1,p25,p50,p75,p99,p999,p100\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched
                .split("init::vmops: Latency percentiles: ")
                .collect();
            assert!(parts.len() >= 2);
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s10_vmops_unmaplat_latency_benchmark() {
    let machine = Machine::determine();
    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("bench-vmops-unmaplat")
        .user_feature("latency")
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let build = build.build();

    let threads = machine.thread_defaults_uniform();
    let file_name = "vmops_unmaplat_benchmark_latency.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
            .cores(machine.max_cores())
            .setaffinity(Vec::new())
            .timeout(35_000 + cores as u64 * 100_000)
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(18192);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like:
            // "Latency percentiles [ns]: maponly,2,4096,1092,1351,1939,3111,4711,9864,2089812"
            // and writes them to a CSV file
            let (prev, matched) =
                    p.exp_regex(r#"init::vmops::unmaplat: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
            output += prev.as_str();
            output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");

            if write_headers {
                let row = "git_rev,benchmark,ncores,memsize,p1,p25,p50,p75,p99,p999,p100\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched
                .split("init::vmops::unmaplat: Latency percentiles: ")
                .collect();
            assert!(parts.len() >= 2);
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s10_fxmark_benchmark() {
    // benchmark naming convention = nameXwrite - mixX10 is - mix benchmark for 10% writes.
    let benchmarks = vec!["mixX0", "mixX10", "mixX100"];
    let num_microbenchs = benchmarks.len() as u64;

    let machine = Machine::determine();
    let mut build = BuildArgs::default()
        .module("init")
        .user_feature("fxmark")
        .release();
    if cfg!(feature = "smoke") {
        build = build.user_feature("smoke");
    }
    let build = build.build();

    let threads = machine.thread_defaults_low_mid_high();

    let file_name = "fxmark_benchmark.csv";
    let _ignore = std::fs::remove_file(file_name);

    fn open_files(benchmark: &str, max_cores: usize, nodes: usize) -> Vec<usize> {
        if benchmark.contains("mix") {
            if cfg!(feature = "smoke") {
                vec![1]
            } else {
                vec![1, max_cores / nodes]
            }
        } else {
            vec![0]
        }
    }

    for benchmark in benchmarks {
        let open_files: Vec<usize> =
            open_files(benchmark, machine.max_cores(), machine.max_numa_nodes());
        for &cores in threads.iter() {
            for &of in open_files.iter() {
                let kernel_cmdline = format!("initargs={}X{}X{}", cores, of, benchmark);
                let mut cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
                    .memory(1024)
                    .timeout(num_microbenchs * (25_000 + cores as u64 * 2000))
                    .cores(machine.max_cores())
                    .setaffinity(Vec::new())
                    .cmd(kernel_cmdline.as_str());

                if cfg!(feature = "smoke") {
                    cmdline = cmdline.memory(8192);
                } else {
                    cmdline = cmdline.memory(core::cmp::max(73728, cores * 2048));
                }

                if cfg!(feature = "smoke") && cores > 2 {
                    cmdline = cmdline.nodes(2);
                } else {
                    cmdline = cmdline.nodes(machine.max_numa_nodes());
                }

                let mut output = String::new();
                let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline)?;

                    // Parse lines like
                    // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                    // write them to a CSV file
                    let expected_lines = if cfg!(feature = "smoke") {
                        1
                    } else {
                        cores * 10
                    };

                    for _i in 0..expected_lines {
                        let (prev, matched) = p.exp_regex(
                            r#"init::fxmark: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#,
                        )?;
                        output += prev.as_str();
                        output += matched.as_str();

                        // Append parsed results to a CSV file
                        let write_headers = !Path::new(file_name).exists();
                        let mut csv_file = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(file_name)
                            .expect("Can't open file");
                        if write_headers {
                            let row =
                         "git_rev,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
                            let r = csv_file.write(row.as_bytes());
                            assert!(r.is_ok());
                        }

                        let parts: Vec<&str> = matched.split("init::fxmark: ").collect();
                        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(parts[1].as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write("\n".as_bytes());
                        assert!(r.is_ok());
                    }

                    output += p.exp_eof()?.as_str();
                    p.process.exit()
                };
                check_for_successful_exit(&cmdline, qemu_run(cores), output);
            }
        }
    }
}

fn memcached_benchmark(
    driver: &'static str,
    cores: usize,
    duration: usize,
) -> Result<rexpect::session::PtySession> {
    fn spawn_memaslap(duration: usize) -> Result<rexpect::session::PtySession> {
        spawn(
            format!("{} -s 172.31.0.10 -t {}s -S 10s", MEMASLAP_BINARY, duration).as_str(),
            Some(25000),
        )
    }
    let mut memaslap = spawn_memaslap(duration)?;

    // Parse this:
    // ```
    // Get Statistics (978827 events)
    // Min:        55
    // Max:      4776
    // Avg:       146
    // Geo:    145.18
    // Std:     32.77
    //
    // Set Statistics (108766 events)
    // Min:        57
    // Max:      4649
    // Avg:       147
    // Geo:    145.91
    // Std:     30.20
    // ```

    let _before = memaslap.exp_string(r#"Get Statistics ("#)?;
    let (_before, get_total) = memaslap.exp_regex(r#"([0-9]+)"#)?;

    let (_before, _line) = memaslap.exp_regex(r#"Min:\s+"#)?;
    let (_before, get_min_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Max:\s+"#)?;
    let (_before, get_max_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Avg:\s+"#)?;
    let (_before, get_avg_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Std:\s+"#)?;
    let (_before, get_std_us) = memaslap.exp_regex(r#"(\d+)"#)?;

    let get_total: usize = get_total.parse().unwrap_or(404);
    let get_min_us: usize = get_min_us.parse().unwrap_or(404);
    let get_max_us: usize = get_max_us.parse().unwrap_or(404);
    let get_avg_us: usize = get_avg_us.parse().unwrap_or(404);
    let get_std_us: usize = get_std_us.parse().unwrap_or(404);

    let _before = memaslap.exp_string(r#"Set Statistics ("#)?;
    let (_before, set_total) = memaslap.exp_regex(r#"([0-9]+)"#)?;

    let (_before, _line) = memaslap.exp_regex(r#"Min:\s+"#)?;
    let (_before, set_min_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Max:\s+"#)?;
    let (_before, set_max_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Avg:\s+"#)?;
    let (_before, set_avg_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Std:\s+"#)?;
    let (_before, set_std_us) = memaslap.exp_regex(r#"(\d+)"#)?;

    let set_total: usize = set_total.parse().unwrap_or(404);
    let set_min_us: usize = set_min_us.parse().unwrap_or(404);
    let set_max_us: usize = set_max_us.parse().unwrap_or(404);
    let set_avg_us: usize = set_avg_us.parse().unwrap_or(404);
    let set_std_us: usize = set_std_us.parse().unwrap_or(404);

    // Append parsed results to a CSV file
    let file_name = "memcached_benchmark.csv";
    // write headers only to a new file
    let write_headers = !Path::new(file_name).exists();
    let csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let mut wtr = WriterBuilder::new()
        .has_headers(write_headers)
        .from_writer(csv_file);

    #[derive(Serialize, Debug, Copy, Clone)]
    struct Record {
        git_rev: &'static str,
        cores: usize,
        duration: usize,
        driver: &'static str,
        get_total: usize,
        get_min_us: usize,
        get_max_us: usize,
        get_avg_us: usize,
        get_std_us: usize,
        set_total: usize,
        set_min_us: usize,
        set_max_us: usize,
        set_avg_us: usize,
        set_std_us: usize,
    }

    let record = Record {
        git_rev: env!("GIT_HASH"),
        cores,
        duration,
        driver,
        get_total,
        get_min_us,
        get_max_us,
        get_avg_us,
        get_std_us,
        set_total,
        set_min_us,
        set_max_us,
        set_avg_us,
        set_std_us,
    };

    wtr.serialize(record).expect("Can't write results");

    Ok(memaslap)
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s10_memcached_benchmark() {
    let _r =
        which::which(MEMASLAP_BINARY).expect("memaslap not installed on host, test will fail!");

    let max_cores = 4;
    let threads = if cfg!(feature = "smoke") {
        vec![1]
    } else {
        vec![1, 2, 4]
    };

    setup_network(1);

    let file_name = "memcached_benchmark.csv";
    let _r = std::fs::remove_file(file_name);
    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:memcached")
        .release()
        .build();

    for nic in &["virtio", "e1000"] {
        for thread in threads.iter() {
            let kernel_cmdline = format!("init=memcached.bin initargs={}", *thread);
            let cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
                .memory(8192)
                .timeout(25_000)
                .cores(max_cores)
                .nodes(1)
                .setaffinity(Vec::new())
                .no_network_setup()
                .cmd(kernel_cmdline.as_str());

            let cmdline = match *nic {
                "virtio" => cmdline.use_virtio(),
                "e1000" => cmdline.use_e1000(),
                _ => unimplemented!("NIC type unknown"),
            };

            let output = String::new();
            let qemu_run = || -> Result<WaitStatus> {
                let mut dhcp_server = spawn_dhcpd()?;
                let mut p = spawn_nrk(&cmdline)?;

                dhcp_server.exp_regex(DHCP_ACK_MATCH)?;

                std::thread::sleep(std::time::Duration::from_secs(6));
                let mut memaslap = memcached_benchmark(nic, *thread, 10)?;

                dhcp_server.send_control('c')?;
                memaslap.process.kill(SIGTERM)?;

                p.process.kill(SIGTERM)
            };

            wait_for_sigterm(&cmdline, qemu_run(), output);
        }
    }
}

#[test]
fn s10_leveldb_benchmark() {
    setup_network(1);

    let machine = Machine::determine();
    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:leveldb-bench")
        .release()
        .build();

    let threads: Vec<usize> = machine
        .thread_defaults_uniform()
        .into_iter()
        // Throw out everything above 28 since we have some non-deterministic
        // bug on larger machines that leads to threads calling sched_yield and
        // no readrandom is performed...
        .filter(|&t| t <= 28)
        .collect();

    // level-DB arguments
    let (reads, num, val_size) = if cfg!(feature = "smoke") {
        (10_000, 5_000, 4096)
    } else {
        (100_000, 50_000, 65535)
    };

    let file_name = "leveldb_benchmark.csv";
    let _r = std::fs::remove_file(file_name);

    for thread in threads.iter() {
        let kernel_cmdline = format!(
            r#"init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
            *thread, *thread, reads, num, val_size
        );
        let mut cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
            .timeout(180_000)
            .cores(machine.max_cores())
            .nodes(2)
            .use_virtio()
            .setaffinity(Vec::new())
            .cmd(kernel_cmdline.as_str())
            .no_network_setup();

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(8192);
        } else {
            cmdline = cmdline.memory(80_000);
        }

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dhcp_server = spawn_dhcpd()?;
            let mut p = spawn_nrk(&cmdline)?;

            output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();

            let (prev, matched) = p.exp_regex(r#"readrandom(.*)"#)?;
            println!("{}", matched);
            output += prev.as_str();
            output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row = "git_rev,benchmark,ncores,reads,num,val_size,operations\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched.split("ops/sec").collect();
            let mut parts: Vec<&str> = parts[0].split(' ').collect();
            parts.pop();
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let out = format!(
                "readrandom,{},{},{},{},{}",
                *thread,
                reads,
                num,
                val_size,
                parts.last().unwrap()
            );
            let r = csv_file.write(out.as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            // cleanup
            dhcp_server.send_control('c')?;
            p.process.kill(SIGTERM)?;
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(), output);
    }
}

#[test]
fn s10_memcached_benchmark_internal() {
    setup_network(1);

    let machine = Machine::determine();
    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:memcached-bench")
        .release()
        .build();

    let threads: Vec<usize> = machine
        .thread_defaults_uniform()
        .into_iter()
        // Throw out everything above 28 since we have some non-deterministic
        // bug on larger machines that leads to threads calling sched_yield and
        // no readrandom is performed...
        .filter(|&t| t <= 28)
        .collect();

    // memcached arguments // currently not there.
    let (qemu_mem, memsize, queries, timeout) = if cfg!(feature = "smoke") {
        (16 * 1024 /* MB */, 16 /* MB */, 2000000, 300_000)
    } else {
        (
            128 * 1024, /* MB */
            32 * 1024,  /* MB */
            50000000,
            600_000,
        )
    };

    let file_name = "memcached_benchmark_internal.csv";
    let _r = std::fs::remove_file(file_name);

    print!("threads: ");
    for thread in threads.iter() {
        print!("{thread} ");
    }
    println!();

    for thread in threads.iter() {
        println!("Running memcached internal benchmark with {thread} threads, {queries} GETs and {memsize}MB memory. ");

        let kernel_cmdline = format!(
            r#"init=memcachedbench.bin initargs={} appcmd='--x-benchmark-mem={} --x-benchmark-queries={}'"#,
            *thread, memsize, queries
        );

        let cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
            .timeout(timeout)
            .cores(machine.max_cores())
            .nodes(2)
            .use_virtio()
            .memory(qemu_mem)
            .setaffinity(Vec::new())
            .cmd(kernel_cmdline.as_str())
            .no_network_setup();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dhcp_server = spawn_dhcpd()?;
            let mut p = spawn_nrk(&cmdline)?;

            output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();

            // match the title
            let (prev, matched) = p.exp_regex(r#"INTERNAL BENCHMARK CONFIGURE"#)?;

            output += prev.as_str();
            output += matched.as_str();

            // x_benchmark_mem = 10 MB
            let (prev, matched) = p.exp_regex(r#"x_benchmark_mem = (\d+) MB"#)?;
            println!("> {}", matched);
            let b_mem = matched.replace("x_benchmark_mem = ", "").replace(" MB", "");

            output += prev.as_str();
            output += matched.as_str();

            // number of threads: 3
            let (prev, matched) = p.exp_regex(r#"number of threads: (\d+)"#)?;
            println!("> {}", matched);
            let b_threads = matched.replace("number of threads: ", "");

            output += prev.as_str();
            output += matched.as_str();

            // number of keys: 131072
            let (prev, matched) = p.exp_regex(r#"number of keys: (\d+)"#)?;
            println!("> {}", matched);

            output += prev.as_str();
            output += matched.as_str();

            let (prev, matched) = p.exp_regex(r#"Executing (\d+) queries with (\d+) threads"#)?;
            println!("> {}", matched);

            output += prev.as_str();
            output += matched.as_str();

            // benchmark took 129 seconds
            let (prev, matched) = p.exp_regex(r#"benchmark took (\d+) ms"#)?;
            println!("> {}", matched);
            let b_time = matched.replace("benchmark took ", "").replace(" ms", "");

            output += prev.as_str();
            output += matched.as_str();

            // benchmark took 7937984 queries / second
            let (prev, matched) = p.exp_regex(r#"benchmark took (\d+) queries / second"#)?;
            println!("> {}", matched);
            let b_thpt = matched
                .replace("benchmark took ", "")
                .replace(" queries / second", "");

            output += prev.as_str();
            output += matched.as_str();

            let (prev, matched) = p.exp_regex(r#"benchmark executed (\d+)"#)?;
            println!("> {}", matched);
            let b_queries = matched
                .replace("benchmark executed ", "")
                .split(' ')
                .next()
                .unwrap()
                .to_string();

            output += prev.as_str();
            output += matched.as_str();

            // Append parsed results to a CSV file
            let write_headers = !Path::new(file_name).exists();
            let mut csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file_name)
                .expect("Can't open file");
            if write_headers {
                let row = "git_rev,benchmark,nthreads,mem,queries,time,thpt\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let out = format!(
                "memcached,{},{},{},{},{}",
                b_threads, b_mem, b_queries, b_time, b_thpt,
            );
            let r = csv_file.write(out.as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            // cleanup
            dhcp_server.send_control('c')?;
            p.process.kill(SIGTERM)?;
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(), output);
    }
}

/// Tests that basic pmem allocation support is functional.
/// TODO: Store persistent data durably and test it.
#[test]
fn s10_pmem_alloc() {
    let machine = Machine::determine();
    // Have at least 2 numa nodes, ensures we test more code-logic
    let nodes = std::cmp::max(2, machine.max_numa_nodes());
    let build = BuildArgs::default()
        .module("init")
        .user_feature("test-pmem-alloc")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
        .nodes(nodes)
        .cores(machine.max_cores())
        .memory(8192)
        .pmem(2048)
        .timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        output += p.exp_string("pmem_alloc OK")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}
