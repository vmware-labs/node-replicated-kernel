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

#[cfg(not(feature = "baremetal"))]
fn rackscale_fxmark_benchmark(transport: RackscaleTransport) {
    let file_name = format!("rackscale_{}_fxmark_benchmark.csv", transport.to_string());
    let _ignore = std::fs::remove_file(file_name.clone());

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
        _arg: Option<()>,
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

    fn cmd_fn(num_cores: usize) -> String {
        //1XmixX0 is - mix benchmark for 0% writes with 1 open file
        format!("initargs={}X1XmixX0", num_cores)
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

    fn cmd_fn(num_cores: usize) -> String {
        format!("initargs={}", num_cores)
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        20_000 * (num_cores) as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 800000 * num_cores as u64
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

// Ignoring this test for now due to synchronization bugs. Seen bugs include
// mutex locking against itself, _lwp_exit returning after a thread has blocked.
/*
#[test]
#[ignore]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_leveldb_benchmark() {
    rackscale_leveldb_benchmark(true);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_leveldb_benchmark(is_shmem: bool) {
    //use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let file_name = if is_shmem {
        "rackscale_shmem_leveldb_benchmark.csv"
    } else {
        "rackscale_ethernet_leveldb_benchmark.csv"
    };
    let _ignore = std::fs::remove_file(file_name);

    let build = Arc::new(
        BuildArgs::default()
            .module("rkapps")
            .user_feature("rkapps:leveldb-bench")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let _build_baseline = Arc::new(
        BuildArgs::default()
            .module("rkapps")
            .user_feature("rkapps:leveldb-bench")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .release()
            .build(),
    );
    //let mut baseline_set = HashSet::new();

    // TODO(rackscale): assert that there are enough threads/nodes on the machine for these settings?
    let machine = Machine::determine();
    let threads = [1, 2, 4, 8, 16];
    let max_cores = *threads.iter().max().unwrap();
    let num_clients = if is_shmem { vec![1, 2, 4] } else { vec![1] };

    // level-DB arguments
    let (reads, num, val_size) = if cfg!(feature = "smoke") {
        (10_000, 5_000, 4096)
    } else {
        // TODO(rackscale): restore these values
        //(100_000, 50_000, 65535)
        (10_000, 5_000, 4096)
    };

    for i in 0..num_clients.len() {
        let nclients = num_clients[i];

        for &cores in threads.iter() {
            let total_cores = cores * nclients;
            if total_cores > max_cores {
                break;
            }

            // TODO(rackscale): this is probably too high, but oh well.
            let timeout = 60_000 * 7;

            // TODO(rackscale): probably scale with nclients?
            let shmem_size = SHMEM_SIZE * 2;

            let all_outputs = Arc::new(Mutex::new(Vec::new()));

            /*
            // TODO: Run baseline test if needed
            if !baseline_set.contains(&total_cores) {
                setup_network(1);
                let mut shmem_server = spawn_shmem_server(SHMEM_PATH, shmem_size)
                    .expect("Failed to start shmem server");

                let baseline_cmdline = format!(
                    r#"init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
                    total_cores, total_cores, reads, num, val_size
                );

                let mut cmdline_baseline =
                    RunnerArgs::new_with_build("userspace-smp", &build_baseline)
                        .timeout(timeout)
                        .shmem_size(shmem_size as usize)
                        .shmem_path(SHMEM_SOCKET)
                        .tap("tap0")
                        .no_network_setup()
                        .workers(1)
                        .cores(total_cores)
                        //.setaffinity(Vec::new())
                        .use_vmxnet3()
                        .cmd(baseline_cmdline.as_str());

                if cfg!(feature = "smoke") {
                    cmdline_baseline = cmdline_baseline.memory(8192);
                } else {
                    cmdline_baseline = cmdline_baseline.memory(80_000);
                }

                let mut output = String::new();
                let mut qemu_run = |baseline_cores| -> Result<WaitStatus> {
                    eprintln!(
                        "\tRunning NrOS leveldb baseline with {} core(s)",
                        baseline_cores
                    );
                    let mut p = spawn_nrk(&cmdline_baseline)?;

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
                        let row =
                            "git_rev,benchmark,nclients,ncores,reads,num,val_size,operations\n";
                        let r = csv_file.write(row.as_bytes());
                        assert!(r.is_ok());
                    }

                    let parts: Vec<&str> = matched.split("ops/sec").collect();
                    let mut parts: Vec<&str> = parts[0].split(" ").collect();
                    parts.pop();
                    let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                    assert!(r.is_ok());
                    let out = format!(
                        "readrandom,{},{},{},{},{},{}",
                        0,
                        total_cores,
                        reads,
                        num,
                        val_size,
                        parts.last().unwrap()
                    );
                    let r = csv_file.write(out.as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write("\n".as_bytes());
                    assert!(r.is_ok());

                    output += p.exp_eof()?.as_str();
                    p.process.exit()
                };

                check_for_successful_exit(&cmdline_baseline, qemu_run(total_cores), output);
                let _ignore = shmem_server.send_control('c');
                baseline_set.insert(total_cores);
            }
            */

            // Now run rackscale test
            setup_network(nclients + 1);
            let (tx, rx) = channel();
            let rx_mut = Arc::new(Mutex::new(rx));

            let mut shmem_server = spawn_shmem_server(SHMEM_SOCKET, SHMEM_PATH, shmem_size)
                .expect("Failed to start shmem server");
            let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

            let controller_cmdline = format!(
                "mode=controller transport={}",
                if is_shmem { "shmem" } else { "ethernet" }
            );

            let mut vm_cores = vec![cores; num_clients + 1];
            vm_cores[0] = 1; // controller vm only has 1 core
            let placement_cores = machine.rackscale_core_affinity(vm_cores);

            // Create controller
            let controller_placement_cores = placement_cores.clone();
            let build1 = build.clone();
            let controller_output_array = all_outputs.clone();
            let controller = std::thread::spawn(move || {
                let mut cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                    .timeout(timeout)
                    .cmd(&controller_cmdline)
                    .shmem_size(shmem_size as usize)
                    .shmem_path(SHMEM_SOCKET)
                    .tap("tap0")
                    .no_network_setup()
                    .workers(nclients + 1)
                    .setaffinity(controller_placement_cores[nclients].clone()) // controller is last in the list of placement cores
                    .use_vmxnet3();

                if cfg!(feature = "smoke") {
                    cmdline_controller = cmdline_controller.memory(8192);
                } else {
                    cmdline_controller = cmdline_controller.memory(80_000);
                }

                let mut output = String::new();
                let mut qemu_run = |controller_clients, application_cores| -> Result<WaitStatus> {
                    eprintln!(
                        "\tRunning rackscale NrOS leveldb controller with {} client(s) for a total of {} application core(s)",
                        controller_clients, application_cores
                    );
                    let mut p = spawn_nrk(&cmdline_controller)?;

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
                        let row =
                            "git_rev,benchmark,nclients,ncores,reads,num,val_size,operations\n";
                        let r = csv_file.write(row.as_bytes());
                        assert!(r.is_ok());
                    }

                    let parts: Vec<&str> = matched.split("ops/sec").collect();
                    let mut parts: Vec<&str> = parts[0].split(" ").collect();
                    parts.pop();
                    let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                    assert!(r.is_ok());
                    let out = format!(
                        "readrandom,{},{},{},{},{},{}",
                        nclients,
                        cores * nclients,
                        reads,
                        num,
                        val_size,
                        parts.last().unwrap()
                    );
                    let r = csv_file.write(out.as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write("\n".as_bytes());
                    assert!(r.is_ok());

                    for _i in 0..nclients {
                        notify_controller_of_termination(&tx);
                    }
                    p.process.kill(SIGTERM)
                };
                let ret = qemu_run(nclients, total_cores);
                controller_output_array
                    .lock()
                    .expect("Failed to get outputs lock")
                    .push((String::from("Controller"), output));

                // This will only find sigterm, that's okay
                wait_for_sigterm_or_successful_exit_no_log(
                    &cmdline_controller,
                    ret,
                    String::from("Controller"),
                );
            });

            let mut clients = Vec::new();
            for nclient in 1..(nclients + 1) {
                let client_cmdline = format!(
                    r#"mode=client transport=shmem init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
                    cores * nclients,
                    cores * nclients,
                    reads,
                    num,
                    val_size
                );

                let my_placement_cores = placement_cores.clone();
                let tap = format!("tap{}", 2 * nclient);
                let my_rx_mut = rx_mut.clone();
                let my_output_array = all_outputs.clone();
                let build2 = build.clone();
                let client = std::thread::spawn(move || {
                    sleep(Duration::from_millis(
                        CLIENT_BUILD_DELAY * (nclient as u64 + 1),
                    ));

                    let mut cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                        .timeout(timeout)
                        .shmem_size(shmem_size as usize)
                        .shmem_path(SHMEM_SOCKET)
                        .tap(&tap)
                        .no_network_setup()
                        .workers(nclients + 1)
                        .cores(cores)
                        .setaffinity(my_placement_cores[nclient - 1].clone())
                        .use_vmxnet3()
                        .nobuild()
                        .cmd(client_cmdline.as_str());

                    cmdline_client = if cfg!(feature = "smoke") {
                        cmdline_client.memory(8192)
                    } else {
                        cmdline_client.memory(80_000)
                    };

                    let mut output = String::new();
                    let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
                        eprintln!(
                            "\tRunning rackscale NrOS leveldb client with {} core(s)",
                            with_cores
                        );
                        let mut p = spawn_nrk(&cmdline_client)?;

                        let rx = my_rx_mut.lock().expect("Failed to get rx lock");
                        let _ = wait_for_client_termination::<()>(&rx);
                        let ret = p.process.kill(SIGTERM);
                        output += p.exp_eof()?.as_str();
                        ret
                    };
                    // Could exit with 'success' or from sigterm, depending on number of clients.
                    let ret = qemu_run(cores);
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
                let outputs = all_outputs.lock().expect("Failed to get ouput lock");
                for (name, output) in outputs.iter() {
                    log_qemu_out_with_name(None, name.to_string(), output.to_string());
                }
            }

            for client_ret in client_rets {
                client_ret.unwrap();
            }
            controller_ret.unwrap();
        }
    }
}
*/

/*
// Ignoring this test for now due to synchronization bugs. Seen bugs include
// mutex locking against itself, _lwp_exit returning after a thread has blocked.
//#[ignore]
#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_leveldb_benchmark() {
    let file_name = "rackscale_shmem_leveldb_benchmark.csv";
    let _ignore = std::fs::remove_file(file_name);

    let built = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:leveldb-bench")
        .release()
        .build();

    // TODO: this logic is duplicated in client match function
    let (reads, num, val_size) = if cfg!(feature = "smoke") {
        (10_000, 5_000, 4096)
    } else {
        // TODO(rackscale): restore these values
        //(100_000, 50_000, 65535)
        (10_000, 5_000, 4096)
    };

    fn controller_match_fn(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
        file_name: &str,
        is_baseline: bool,
        arg: usize,
    ) -> Result<()> {
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

        let num_replicas = if is_baseline { 0 } else { num_clients };

        let parts: Vec<&str> = matched.split("ops/sec").collect();
        let mut parts: Vec<&str> = parts[0].split(" ").collect();
        parts.pop();
        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
        assert!(r.is_ok());
        let out = format!(
            "readrandom,{},{},{},{},{},{}",
            num_clients,
            num_clients,
            cores_per_client * num_clients,
            reads,
            num,
            val_size,
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

    fn cmd_fn(num_cores: usize) -> String {
        format!("initargs={}", num_cores)
    }
    fn baseline_timeout_fn(num_cores: usize) -> u64 {
        20_000 * (num_cores) as u64
    }
    fn rackscale_timeout_fn(num_cores: usize) -> u64 {
        120_000 + 800000 * num_cores as u64
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
*/
