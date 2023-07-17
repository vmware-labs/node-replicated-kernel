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
use std::sync::{mpsc::channel, Mutex};

use rexpect::errors::*;
use rexpect::process::signal::{SIGKILL, SIGTERM};
use rexpect::process::wait::WaitStatus;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{
    get_shmem_names, notify_controller_of_termination, setup_network, spawn_dcm, spawn_nrk,
    spawn_shmem_server, wait_for_client_termination, CLIENT_BUILD_DELAY, SHMEM_SIZE,
};
use testutils::runner_args::{
    check_for_successful_exit, log_qemu_out_with_name, wait_for_sigterm_or_successful_exit_no_log,
    RackscaleMode, RunnerArgs,
};

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_fxmark_benchmark() {
    rackscale_fxmark_benchmark(true);
}

#[test]
#[ignore]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_ethernet_fxmark_benchmark() {
    rackscale_fxmark_benchmark(false);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_fxmark_benchmark(is_shmem: bool) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    // benchmark naming convention = nameXwrite - mixX10 is - mix benchmark for 10% writes.
    let benchmarks = if cfg!(feature = "smoke") {
        vec!["mixX0"]
    } else {
        // For rackscale, for now, just do 100% reads.
        vec!["mixX0"]
        //vec!["mixX0", "mixX10", "mixX100"]
    };

    let file_name = if is_shmem {
        "rackscale_shmem_fxmark_benchmark.csv"
    } else {
        "rackscale_ethernet_fxmark_benchmark.csv"
    };
    let _ignore = std::fs::remove_file(file_name);

    let (build, build_baseline) = {
        let mut build = BuildArgs::default()
            .module("init")
            .user_feature("fxmark")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .release();
        if cfg!(feature = "smoke") {
            build = build.user_feature("smoke");
        }
        let baseline_build = build.clone();
        build = build.kernel_feature("rackscale");
        (Arc::new(build.build()), Arc::new(baseline_build.build()))
    };

    let open_files = 1;
    let machine = Machine::determine();
    let shmem_size = SHMEM_SIZE;

    let max_cores = if cfg!(feature = "smoke") {
        1
    } else {
        machine.max_cores()
    };
    let max_numa = machine.max_numa_nodes();
    let cores_per_node = core::cmp::max(1, max_cores / max_numa);

    for benchmark in benchmarks {
        // Run the baseline test
        if cfg!(feature = "baseline") {
            setup_network(1);
            let mut num_nodes = 1;
            let mut cores = 1;
            while cores < max_cores {
                // Round up to get the number of clients
                let new_num_nodes = (cores + (cores_per_node - 1)) / cores_per_node;

                // Make sure cores are divisible by num replicas (nodes) if num replicas changes.
                if num_nodes != new_num_nodes {
                    num_nodes = new_num_nodes;

                    // ensure total cores is divisible by num nodes
                    cores = cores - (cores % num_nodes);
                }

                let timeout = 120_000 + 20000 * cores as u64;

                eprintln!(
                        "\tRunning NrOS fxmark {} baseline with {} core(s) and {} node(s) and {} open files",
                        benchmark, cores, num_nodes, open_files
                    );

                let vm_cores = vec![cores / num_nodes; num_nodes]; // replicas
                let placement_cores = machine.rackscale_core_affinity(vm_cores);
                let mut all_placement_cores = Vec::new();
                let placement_offset = placement_cores[0].0;
                for placement in placement_cores {
                    all_placement_cores.extend(placement.1);
                }

                let baseline_cmdline = format!(
                    "transport={} initargs={}X{}X{}",
                    if is_shmem { "shmem" } else { "ethernet" },
                    cores,
                    open_files,
                    benchmark
                );

                let (shmem_socket, shmem_file) =
                    get_shmem_names(None, cfg!(feature = "affinity-shmem"));
                let shmem_affinity = if cfg!(feature = "affinity-shmem") {
                    Some(0)
                } else {
                    None
                };
                let mut shmem_server =
                    spawn_shmem_server(&shmem_socket, &shmem_file, shmem_size, shmem_affinity)
                        .expect("Failed to start shmem server");

                let mut cmdline_baseline =
                    RunnerArgs::new_with_build("userspace-smp", &build_baseline)
                        .timeout(timeout)
                        .shmem_size(vec![shmem_size as usize])
                        .shmem_path(vec![shmem_socket])
                        .tap("tap0")
                        .workers(1)
                        .cores(cores)
                        .nodes(num_nodes)
                        .node_offset(placement_offset)
                        .setaffinity(all_placement_cores)
                        .use_vmxnet3()
                        .cmd(baseline_cmdline.as_str());

                if cfg!(feature = "smoke") {
                    cmdline_baseline = cmdline_baseline.memory(8192);
                } else {
                    cmdline_baseline = cmdline_baseline.memory(core::cmp::max(73728, cores * 2048));
                }

                let mut output = String::new();
                let mut qemu_run = |baseline_cores| -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_baseline)?;

                    // Parse lines like
                    // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                    // write them to a CSV file
                    let expected_lines = if cfg!(feature = "smoke") {
                        1
                    } else {
                        baseline_cores * 10
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
                            let row = "git_rev,nclients,nreplicas,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
                            let r = csv_file.write(row.as_bytes());
                            assert!(r.is_ok());
                        }

                        let parts: Vec<&str> = matched.split("init::fxmark: ").collect();
                        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(format!("{},", 0).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(format!("{},", num_nodes).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(parts[1].as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write("\n".as_bytes());
                        assert!(r.is_ok());
                    }

                    output += p.exp_eof()?.as_str();
                    p.process.exit()
                };
                check_for_successful_exit(&cmdline_baseline, qemu_run(cores), output);
                let _ignore = shmem_server.send_control('c');

                if cores == 1 {
                    cores = 0;
                }

                if num_nodes == 3 {
                    cores += 3;
                } else {
                    cores += 4;
                }
            }
        }

        // Run the rackscale test
        let mut num_clients = 1;
        setup_network(num_clients + 1);
        let mut total_cores = 1;
        while total_cores < max_cores {
            // Round up to get the number of clients
            let new_num_clients = (total_cores + (cores_per_node - 1)) / cores_per_node;

            // Do network setup if number of clients has changed.
            if num_clients != new_num_clients {
                num_clients = new_num_clients;
                setup_network(num_clients + 1);

                // ensure total cores is divisible by num clients
                total_cores = total_cores - (total_cores % num_clients);
            }
            let cores = total_cores / num_clients;
            let all_outputs = Arc::new(Mutex::new(Vec::new()));

            let mut vm_cores = vec![cores; num_clients + 1];
            vm_cores[0] = 1; // controller vm only has 1 core
            let placement_cores = machine.rackscale_core_affinity(vm_cores);
            let timeout = 120_000 + 20000 * (cores + num_clients) as u64;

            eprintln!(
                    "\tRunning fxmark test {} with {:?} total core(s), {:?} client(s) (cores_per_client={:?}) and {:?} open files",
                    benchmark, total_cores, num_clients, cores, open_files
                );

            let (tx, rx) = channel();
            let rx_mut = Arc::new(Mutex::new(rx));

            let mut shmem_sockets = Vec::new();
            let mut shmem_servers = Vec::new();
            for i in 0..(num_clients + 1) {
                let shmem_affinity = if cfg!(feature = "affinity-shmem") {
                    Some(placement_cores[i].0)
                } else {
                    None
                };
                let (shmem_socket, shmem_file) =
                    get_shmem_names(Some(i), cfg!(feature = "affinity-shmem"));
                let shmem_server =
                    spawn_shmem_server(&shmem_socket, &shmem_file, shmem_size, shmem_affinity)
                        .expect("Failed to start shmem server");
                shmem_sockets.push(shmem_socket);
                shmem_servers.push(shmem_server);
            }

            let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

            let controller_cmdline =
                format!("transport={}", if is_shmem { "shmem" } else { "ethernet" });

            // Create controller
            let build1 = build.clone();
            let controller_output_array = all_outputs.clone();
            let controller_placement_cores = placement_cores.clone();
            let my_shmem_sockets = shmem_sockets.clone();
            let controller = std::thread::spawn(move || {
                let mut cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                    .timeout(timeout)
                    .cmd(&controller_cmdline)
                    .mode(RackscaleMode::Controller)
                    .shmem_size(vec![shmem_size as usize; num_clients + 1])
                    .shmem_path(my_shmem_sockets)
                    .nodes(1)
                    .node_offset(controller_placement_cores[0].0)
                    .tap("tap0")
                    .setaffinity(controller_placement_cores[0].1.clone())
                    .no_network_setup()
                    .workers(num_clients + 1)
                    .use_vmxnet3();

                if cfg!(feature = "smoke") {
                    cmdline_controller = cmdline_controller.memory(8192);
                } else {
                    cmdline_controller =
                        cmdline_controller.memory(core::cmp::max(73728, cores * 2048));
                }

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_controller)?;

                    // Parse lines like
                    // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                    // write them to a CSV file
                    let expected_lines = if cfg!(feature = "smoke") {
                        1
                    } else {
                        total_cores * 10
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
                            let row = "git_rev,nclients,nreplicas,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
                            let r = csv_file.write(row.as_bytes());
                            assert!(r.is_ok());
                        }

                        let parts: Vec<&str> = matched.split("init::fxmark: ").collect();
                        let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(format!("{},", num_clients).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(format!("{},", num_clients).as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write(parts[1].as_bytes());
                        assert!(r.is_ok());
                        let r = csv_file.write("\n".as_bytes());
                        assert!(r.is_ok());
                    }

                    for _i in 0..num_clients {
                        notify_controller_of_termination(&tx);
                    }
                    p.process.kill(SIGTERM)
                };
                let ret = qemu_run();
                controller_output_array
                    .lock()
                    .expect("Failed to get output mutex")
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
                    "transport={} initargs={}X{}X{}",
                    if is_shmem { "shmem" } else { "ethernet" },
                    total_cores,
                    open_files,
                    benchmark
                );

                let tap = format!("tap{}", 2 * nclient);
                let my_rx_mut = rx_mut.clone();
                let my_output_array = all_outputs.clone();
                let my_placement_cores = placement_cores.clone();
                let my_shmem_sockets = shmem_sockets.clone();
                let build2 = build.clone();
                let client = std::thread::spawn(move || {
                    sleep(Duration::from_millis(
                        CLIENT_BUILD_DELAY * (nclient as u64 + 1),
                    ));
                    let mut cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                        .timeout(timeout)
                        .mode(RackscaleMode::Client)
                        .shmem_size(vec![shmem_size as usize; num_clients + 1])
                        .shmem_path(my_shmem_sockets)
                        .tap(&tap)
                        .no_network_setup()
                        .workers(num_clients + 1)
                        .cores(cores)
                        .nodes(1)
                        .node_offset(my_placement_cores[nclient].0)
                        .setaffinity(my_placement_cores[nclient].1.clone())
                        .use_vmxnet3()
                        .nobuild()
                        .cmd(kernel_cmdline.as_str());

                    if cfg!(feature = "smoke") {
                        cmdline_client = cmdline_client.memory(8192);
                    } else {
                        cmdline_client = cmdline_client.memory(core::cmp::max(73728, cores * 2048));
                    }

                    let mut output = String::new();
                    let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
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
                        .expect("Failed to get lock for outputs")
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

            for shmem_server in shmem_servers.iter_mut() {
                let _ignore = shmem_server.send_control('c');
            }
            let _ignore = dcm.process.kill(SIGKILL);

            // If there's been an error, print everything
            if controller_ret.is_err() || (&client_rets).into_iter().any(|ret| ret.is_err()) {
                let outputs = all_outputs.lock().expect("Failed to get lock for outputs");
                for (name, output) in outputs.iter() {
                    log_qemu_out_with_name(None, name.to_string(), output.to_string());
                }
            }

            for client_ret in client_rets {
                client_ret.unwrap();
            }
            controller_ret.unwrap();

            if total_cores == 1 {
                total_cores = 0;
            }

            if num_clients == 3 {
                total_cores += 3;
            } else {
                total_cores += 4;
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum VMOpsBench {
    MapLatency,
    MapThroughput,
    UnmapLatency,
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_maptput_benchmark() {
    rackscale_vmops_benchmark(true, VMOpsBench::MapThroughput);
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_maplat_benchmark() {
    rackscale_vmops_benchmark(true, VMOpsBench::MapLatency);
}

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_vmops_unmaplat_benchmark() {
    rackscale_vmops_benchmark(true, VMOpsBench::UnmapLatency);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_vmops_benchmark(is_shmem: bool, benchtype: VMOpsBench) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let transport_str = if is_shmem { "shmem" } else { "ethernet" };
    let testname_str = match benchtype {
        VMOpsBench::MapThroughput => "vmops",
        VMOpsBench::MapLatency => "vmops_latency",
        VMOpsBench::UnmapLatency => "vmops_unmaplat",
    };
    let file_name = Arc::new(format!(
        "rackscale_{}_{}_benchmark.csv",
        transport_str, testname_str
    ));
    let _ignore = std::fs::remove_file(file_name.as_ref());

    let build = Arc::new({
        let mut build = BuildArgs::default().module("init");

        if benchtype == VMOpsBench::UnmapLatency {
            build = build.user_feature("bench-vmops-unmaplat");
        } else {
            build = build.user_feature("bench-vmops");
        }
        if benchtype == VMOpsBench::MapLatency || benchtype == VMOpsBench::UnmapLatency {
            build = build.user_feature("latency");
        }
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

        if benchtype == VMOpsBench::UnmapLatency {
            build = build.user_feature("bench-vmops-unmaplat");
        } else {
            build = build.user_feature("bench-vmops");
        }
        if benchtype == VMOpsBench::MapLatency || benchtype == VMOpsBench::UnmapLatency {
            build = build.user_feature("latency");
        }
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
    let max_cores = if cfg!(feature = "smoke") {
        1
    } else {
        machine.max_cores()
    };
    let baseline_shmem_size = if max_cores <= 32 {
        SHMEM_SIZE * 2
    } else {
        SHMEM_SIZE * 4
    };
    let shmem_size = SHMEM_SIZE;

    let max_numa = machine.max_numa_nodes();
    let cores_per_node = core::cmp::max(1, max_cores / max_numa);

    if cfg!(feature = "baseline") {
        // Run the baseline test
        setup_network(1);
        let mut num_nodes = 1;
        let mut cores = 1;
        while cores < max_cores {
            // Round up to get the number of clients
            let new_num_nodes = (cores + (cores_per_node - 1)) / cores_per_node;

            // Make sure cores are divisible by num replicas (nodes) if num replicas changes.
            if num_nodes != new_num_nodes {
                num_nodes = new_num_nodes;

                // ensure total cores is divisible by num nodes
                cores = cores - (cores % num_nodes);
            }

            let timeout = 20_000 * (cores) as u64;
            eprintln!(
                "\tRunning NrOS vmops baseline with {} core(s) and {} node(s)",
                cores, num_nodes
            );

            let (shmem_socket, shmem_file) =
                get_shmem_names(None, cfg!(feature = "affinity-shmem"));
            let shmem_affinity = if cfg!(feature = "affinity-shmem") {
                Some(0)
            } else {
                None
            };
            let mut shmem_server = spawn_shmem_server(
                &shmem_socket,
                &shmem_file,
                baseline_shmem_size,
                shmem_affinity,
            )
            .expect("Failed to start shmem server");

            let baseline_cmdline = format!("initargs={}", cores);
            let baseline_file_name = file_name.clone();

            let vm_cores = vec![cores / num_nodes; num_nodes]; // client vms
            let placement_cores = machine.rackscale_core_affinity(vm_cores);
            let mut all_placement_cores = Vec::new();
            let placement_offset = placement_cores[0].0;
            for placement in placement_cores {
                all_placement_cores.extend(placement.1);
            }

            let mut cmdline_baseline = RunnerArgs::new_with_build("userspace-smp", &build_baseline)
                .timeout(timeout)
                .shmem_size(vec![baseline_shmem_size as usize])
                .shmem_path(vec![shmem_socket])
                .tap("tap0")
                .workers(1)
                .cores(cores)
                .nodes(num_nodes)
                .node_offset(placement_offset)
                .setaffinity(all_placement_cores)
                .use_vmxnet3()
                .cmd(baseline_cmdline.as_str());

            if cfg!(feature = "smoke") {
                cmdline_baseline = cmdline_baseline.memory(10 * 1024);
            } else {
                cmdline_baseline = cmdline_baseline.memory(48 * 1024);
            }

            let mut output = String::new();
            let mut qemu_run = |baseline_cores| -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_baseline)?;

                let expected_lines = if cfg!(feature = "smoke") {
                    1
                } else if benchtype == VMOpsBench::MapThroughput {
                    baseline_cores * 11
                } else {
                    1
                };

                for _i in 0..expected_lines {
                    let (prev, matched) = match benchtype {
                    VMOpsBench::MapThroughput => p.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                    VMOpsBench::MapLatency => p.exp_regex(r#"init::vmops: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                    VMOpsBench::UnmapLatency => p.exp_regex(r#"init::vmops::unmaplat: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                };
                    output += prev.as_str();
                    output += matched.as_str();

                    // Append parsed results to a CSV file
                    let write_headers = !Path::new(baseline_file_name.as_ref()).exists();
                    let mut csv_file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(baseline_file_name.as_ref())
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
                    let r = csv_file.write(format!("{},", 0).as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write(format!("{},", num_nodes).as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write(parts[1].as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write("\n".as_bytes());
                    assert!(r.is_ok());
                }
                output += p.exp_eof()?.as_str();
                p.process.exit()
            };
            check_for_successful_exit(&cmdline_baseline, qemu_run(cores), output);
            let _ignore = shmem_server.send_control('c');

            if cores == 1 {
                cores = 0;
            }

            if num_nodes == 3 {
                cores += 3;
            } else {
                cores += 4;
            }
        }
    }

    // Run the rackscale test
    let mut num_clients = 1;
    setup_network(num_clients + 1);
    let mut total_cores = 1;
    while total_cores < max_cores {
        // Round up to get the number of clients
        let new_num_clients = (total_cores + (cores_per_node - 1)) / cores_per_node;

        // Do network setup if number of clients has changed.
        if num_clients != new_num_clients {
            num_clients = new_num_clients;
            setup_network(num_clients + 1);

            // ensure total cores is divisible by num clients
            total_cores = total_cores - (total_cores % num_clients);
        }
        let cores = total_cores / num_clients;

        eprintln!(
            "\tRunning vmops test with {:?} total core(s), {:?} client(s) (cores_per_client={:?})",
            total_cores, num_clients, cores
        );
        let timeout = 120_000 + 800000 * total_cores as u64;
        let all_outputs = Arc::new(Mutex::new(Vec::new()));

        let mut vm_cores = vec![cores; num_clients + 1];
        vm_cores[0] = 1; // controller vm only has 1 core
        let placement_cores = machine.rackscale_core_affinity(vm_cores);

        let (tx, rx) = channel();
        let rx_mut = Arc::new(Mutex::new(rx));

        let mut shmem_sockets = Vec::new();
        let mut shmem_servers = Vec::new();
        for i in 0..(num_clients + 1) {
            let shmem_affinity = if cfg!(feature = "affinity-shmem") {
                Some(placement_cores[i].0)
            } else {
                None
            };
            let (shmem_socket, shmem_file) =
                get_shmem_names(Some(i), cfg!(feature = "affinity-shmem"));
            let shmem_server =
                spawn_shmem_server(&shmem_socket, &shmem_file, shmem_size, shmem_affinity)
                    .expect("Failed to start shmem server");
            shmem_sockets.push(shmem_socket);
            shmem_servers.push(shmem_server);
        }

        let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

        let controller_cmdline =
            format!("transport={}", if is_shmem { "shmem" } else { "ethernet" });

        // Create controller
        let build1 = build.clone();
        let controller_output_array = all_outputs.clone();
        let controller_file_name = file_name.clone();
        let controller_placement_cores = placement_cores.clone();
        let my_shmem_sockets = shmem_sockets.clone();
        let controller = std::thread::spawn(move || {
            let mut cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd(&controller_cmdline)
                .mode(RackscaleMode::Controller)
                .shmem_size(vec![shmem_size as usize; num_clients + 1])
                .shmem_path(my_shmem_sockets)
                .tap("tap0")
                .nodes(1)
                .node_offset(controller_placement_cores[0].0)
                .no_network_setup()
                .workers(num_clients + 1)
                .setaffinity(controller_placement_cores[0].1.clone())
                .use_vmxnet3();

            if cfg!(feature = "smoke") {
                cmdline_controller = cmdline_controller.memory(10 * 1024);
            } else {
                cmdline_controller = cmdline_controller.memory(48 * 1024);
            }

            let mut output = String::new();
            let mut qemu_run = |controller_clients, application_cores| -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;
                let expected_lines = if cfg!(feature = "smoke") {
                    1
                } else if benchtype == VMOpsBench::MapThroughput {
                    application_cores * 11
                } else {
                    1
                };

                for _i in 0..expected_lines {
                    let (prev, matched) = match benchtype {
                        VMOpsBench::MapThroughput => p.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                        VMOpsBench::MapLatency => p.exp_regex(r#"init::vmops: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                        VMOpsBench::UnmapLatency => p.exp_regex(r#"init::vmops::unmaplat: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?,
                    };
                    output += prev.as_str();
                    output += matched.as_str();

                    // Append parsed results to a CSV file
                    let write_headers = !Path::new(controller_file_name.as_ref()).exists();
                    let mut csv_file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(controller_file_name.as_ref())
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
                    let r = csv_file.write(format!("{},", controller_clients).as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write(format!("{},", controller_clients).as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write(parts[1].as_bytes());
                    assert!(r.is_ok());
                    let r = csv_file.write("\n".as_bytes());
                    assert!(r.is_ok());
                }

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
                "transport={} initargs={}",
                if is_shmem { "shmem" } else { "ethernet" },
                total_cores,
            );

            let tap = format!("tap{}", 2 * nclient);
            let my_rx_mut = rx_mut.clone();
            let my_output_array = all_outputs.clone();
            let my_placement_cores = placement_cores.clone();
            let build2 = build.clone();
            let my_shmem_sockets = shmem_sockets.clone();
            let client = std::thread::spawn(move || {
                sleep(Duration::from_millis(
                    CLIENT_BUILD_DELAY * (nclient as u64 + 1),
                ));
                let mut cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                    .timeout(timeout)
                    .mode(RackscaleMode::Client)
                    .shmem_size(vec![shmem_size as usize; num_clients + 1])
                    .shmem_path(my_shmem_sockets)
                    .tap(&tap)
                    .no_network_setup()
                    .workers(num_clients + 1)
                    .cores(cores)
                    .nodes(1)
                    .node_offset(my_placement_cores[nclient].0)
                    .setaffinity(my_placement_cores[nclient].1.clone())
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
        for shmem_server in shmem_servers.iter_mut() {
            let _ignore = shmem_server.send_control('c');
        }
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

        if total_cores == 1 {
            total_cores = 0;
        }

        if num_clients == 3 {
            total_cores += 3;
        } else {
            total_cores += 4;
        }
    }
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
