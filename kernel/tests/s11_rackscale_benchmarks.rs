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

use testutils::builder::BuildArgs;
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
        120_000 + 20000 * num_cores as u64
    }
    fn mem_fn(num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            core::cmp::max(73728, num_cores * 2048)
        }
    }
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn: timeout_fn,
        rackscale_timeout_fn: timeout_fn,
        controller_mem_fn: mem_fn,
        client_mem_fn: mem_fn,
        baseline_mem_fn: mem_fn,
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
    test.file_name = file_name.clone();
    test.arg = Some(benchtype);

    fn cmd_fn(num_cores: usize, _arg: Option<VMOpsBench>) -> String {
        format!("initargs={}", num_cores)
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        20_000 * num_cores as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 60_000 * num_cores as u64
    }
    fn mem_fn(_num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            10 * 1024
        } else {
            48 * 1024
        }
    }
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        controller_mem_fn: mem_fn,
        client_mem_fn: mem_fn,
        baseline_mem_fn: mem_fn,
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

// Ignoring this test for now due to synchronization bugs. Seen bugs include
// mutex locking against itself, _lwp_exit returning after a thread has blocked.
/*
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
    test.file_name = file_name.to_string();
    test.arg = Some(config);
    test.client_build_delay *= 2;
    test.run_dhcpd_for_baseline = true;

    fn cmd_fn(num_cores: usize, arg: Option<LevelDBConfig>) -> String {
        let config = arg.expect("missing leveldb config");
        format!(
            r#"init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
            num_cores, num_cores, config.reads, config.num, config.val_size
        )
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        20_000 * num_cores as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        180_000 + 60_000 * num_cores as u64
    }
    fn mem_fn(_num_cores: usize, is_smoke: bool) -> usize {
        if is_smoke {
            8192
        } else {
            80_000
        }
    }
    let bench = RackscaleBench {
        test,
        cmd_fn,
        baseline_timeout_fn,
        rackscale_timeout_fn,
        controller_mem_fn: mem_fn,
        client_mem_fn: mem_fn,
        baseline_mem_fn: mem_fn,
    };

    if cfg!(feature = "baseline") {
        bench.run_bench(true, is_smoke);
    }
    bench.run_bench(false, is_smoke);
}
*/

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_memcached_benchmark_internal() {
    rackscale_memcached_benchmark(true);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_memcached_benchmark(is_shmem: bool) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let transport_str = if is_shmem { "shmem" } else { "ethernet" };
    let file_name = Arc::new(format!(
        "rackscale_{}_memcached_benchmark.csv",
        transport_str
    ));
    let _ignore = std::fs::remove_file(file_name.as_ref());

    let build = Arc::new({
        let mut build = BuildArgs::default().module("init");

        build = build.user_feature("rkapps:memcached-bench");

        build = build
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release();
        if cfg!(feature = "smoke") {
            build = build.user_feature("smoke");
        }
        build.build()
    });

    let build_baseline = Arc::new({
        let mut build = BuildArgs::default().module("init");

        build = build.user_feature("rkapps:memcached-bench");

        build = build
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .release();
        if cfg!(feature = "smoke") {
            build = build.user_feature("smoke");
        }
        build.build()
    });

    let machine = Machine::determine();
    let shmem_size = if cfg!(feature = "smoke") || machine.max_cores() <= 32 {
        SHMEM_SIZE * 2
    } else {
        SHMEM_SIZE * 4
    };

    let max_cores = if cfg!(feature = "smoke") {
        1
    } else {
        machine.max_cores()
    };
    let cores_per_node = machine.max_cores() / machine.max_numa_nodes();

    if cfg!(feature = "baseline") {
        // Run the baseline test
        setup_network(1);
        let mut num_nodes = 1;
        for cores in (0..max_cores).step_by(4) {
            let cores = if cores == 0 { 1 } else { cores };
            if num_nodes * cores_per_node < cores {
                num_nodes = 2 * num_nodes;
            }
            let timeout = 20_000 * (cores) as u64;
            eprintln!(
                "\tRunning Memcached baseline with {} core(s) and {} node(s)",
                cores, num_nodes
            );

            let mut shmem_server =
                spawn_shmem_server(SHMEM_PATH, shmem_size).expect("Failed to start shmem server");

            let baseline_cmdline = format!("initargs={}", cores);
            let baseline_file_name = file_name.clone();

            let vm_cores = vec![cores / num_nodes; num_nodes]; // client vms
            let mut placement_cores = machine.rackscale_core_affinity(vm_cores);
            let mut affinity_cores = Vec::new();
            for mut corelist in placement_cores.iter_mut() {
                affinity_cores.append(&mut corelist);
            }

            let mut cmdline_baseline = RunnerArgs::new_with_build("userspace-smp", &build_baseline)
                .timeout(timeout)
                .shmem_size(shmem_size as usize)
                .shmem_path(SHMEM_PATH)
                .tap("tap0")
                .workers(1)
                .cores(cores)
                .nodes(num_nodes)
                .setaffinity(affinity_cores)
                .use_vmxnet3()
                .cmd(baseline_cmdline.as_str());

            if cfg!(feature = "smoke") {
                cmdline_baseline = cmdline_baseline.memory(10 * 1024);
            } else {
                cmdline_baseline = cmdline_baseline.memory(48 * 1024);
            }

            let mut output = String::new();
            let mut qemu_run = |_baseline_cores| -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_baseline)?;

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
                    .split(" ")
                    .next()
                    .unwrap()
                    .to_string();

                output += prev.as_str();
                output += matched.as_str();

                // Append parsed results to a CSV file
                let write_headers = !Path::new(baseline_file_name.as_str()).exists();
                let mut csv_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(baseline_file_name.as_str())
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

                output += p.exp_eof()?.as_str();
                p.process.exit()
            };
            check_for_successful_exit(&cmdline_baseline, qemu_run(cores), output);
            let _ignore = shmem_server.send_control('c');
        }
    }

    // Run the rackscale test
    let mut num_clients = 1;
    setup_network(num_clients + 1);
    for total_cores in (0..max_cores).step_by(4) {
        let total_cores = if total_cores == 0 { 1 } else { total_cores };
        if num_clients * cores_per_node < total_cores {
            num_clients = num_clients * 2;
            setup_network(num_clients + 1);
        }
        let cores = total_cores / num_clients;

        eprintln!(
            "\tRunning Memcached test with {:?} total core(s), {:?} client(s) (cores_per_client={:?})",
            total_cores, num_clients, cores
        );
        let timeout = 120_000 + 800000 * total_cores as u64;
        let all_outputs = Arc::new(Mutex::new(Vec::new()));

        let mut vm_cores = vec![cores; num_clients]; // client vms
        vm_cores.push(1); // controller
        let placement_cores = machine.rackscale_core_affinity(vm_cores);

        let (tx, rx) = channel();
        let rx_mut = Arc::new(Mutex::new(rx));

        let mut shmem_server =
            spawn_shmem_server(SHMEM_PATH, shmem_size).expect("Failed to start shmem server");
        let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

        let controller_cmdline = format!(
            "mode=controller transport={}",
            if is_shmem { "shmem" } else { "ethernet" }
        );

        // Create controller
        let build1 = build.clone();
        let controller_output_array = all_outputs.clone();
        let controller_file_name = file_name.clone();
        let controller_placement_cores = placement_cores.clone();
        let controller = std::thread::spawn(move || {
            let mut cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd(&controller_cmdline)
                .shmem_size(shmem_size as usize)
                .shmem_path(SHMEM_PATH)
                .tap("tap0")
                .no_network_setup()
                .workers(num_clients + 1)
                .setaffinity(controller_placement_cores[num_clients].clone())
                .use_vmxnet3();

            if cfg!(feature = "smoke") {
                cmdline_controller = cmdline_controller.memory(10 * 1024);
            } else {
                cmdline_controller = cmdline_controller.memory(48 * 1024);
            }

            let mut output = String::new();
            let mut qemu_run = |_controller_clients, _application_cores| -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

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
                    .split(" ")
                    .next()
                    .unwrap()
                    .to_string();

                output += prev.as_str();
                output += matched.as_str();

                // Append parsed results to a CSV file
                let write_headers = !Path::new(controller_file_name.as_str()).exists();
                let mut csv_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(controller_file_name.as_str())
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

                for _i in 0..num_clients {
                    notify_controller_of_termination(&tx);
                }
                p.process.kill(SIGTERM)
            };
            let ret = qemu_run(num_clients, total_cores);
            controller_output_array
                .lock()
                .expect("Failed to get output lock")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        });

        let mut clients = Vec::new();
        for nclient in 1..(num_clients + 1) {
            let kernel_cmdline = format!(
                "mode=client transport={} initargs={}",
                if is_shmem { "shmem" } else { "ethernet" },
                total_cores,
            );

            let tap = format!("tap{}", 2 * nclient);
            let my_rx_mut = rx_mut.clone();
            let my_output_array = all_outputs.clone();
            let my_placement_cores = placement_cores.clone();
            let build2 = build.clone();
            let client = std::thread::spawn(move || {
                sleep(Duration::from_millis(
                    CLIENT_BUILD_DELAY * (nclient as u64 + 1),
                ));
                let mut cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                    .timeout(timeout)
                    .shmem_size(shmem_size as usize)
                    .shmem_path(SHMEM_PATH)
                    .tap(&tap)
                    .no_network_setup()
                    .workers(num_clients + 1)
                    .cores(cores)
                    .setaffinity(my_placement_cores[nclient - 1].clone())
                    .use_vmxnet3()
                    .nobuild()
                    .cmd(kernel_cmdline.as_str());

                if cfg!(feature = "smoke") {
                    cmdline_client = cmdline_client.memory(10 * 1024);
                } else {
                    cmdline_client = cmdline_client.memory(48 * 1024);
                }

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;
                    let rx = my_rx_mut.lock().expect("Failed to get rx lock");
                    let _ = wait_for_client_termination::<()>(&rx);
                    let ret = p.process.kill(SIGTERM);
                    output += p.exp_eof()?.as_str();
                    ret
                };
                // Could exit with 'success' or from sigterm, depending on number of clients.
                let ret = qemu_run();
                my_output_array
                    .lock()
                    .expect("Failed to get output lock")
                    .push((format!("Client{}", nclient), output));
                wait_for_sigterm_or_successful_exit_no_log(
                    &cmdline_client,
                    ret,
                    format!("Client{}", nclient),
                );
            });
            clients.push(client)
        }

        let controller_ret = controller.join();
        let mut client_rets = Vec::new();
        for client in clients {
            client_rets.push(client.join());
        }
        let _ignore = shmem_server.send_control('c');
        let _ignore = dcm.process.kill(SIGKILL);

        // If there's been an error, print everything
        if controller_ret.is_err() || (&client_rets).into_iter().any(|ret| ret.is_err()) {
            let outputs = all_outputs.lock().expect("Failed to get output lock");
            for (name, output) in outputs.iter() {
                log_qemu_out_with_name(None, name.to_string(), output.to_string());
            }
            if controller_ret.is_err() {
                let dcm_log = dcm.exp_eof();
                if dcm_log.is_ok() {
                    log_qemu_out_with_name(None, "DCM".to_string(), dcm_log.unwrap());
                } else {
                    eprintln!("Failed to print DCM log.");
                }
            }
        }

        for client_ret in client_rets {
            client_ret.unwrap();
        }
        controller_ret.unwrap();
    }
}
