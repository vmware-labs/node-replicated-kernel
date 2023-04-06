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
use std::sync::mpsc::channel;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{
    notify_controller_of_termination, setup_network, spawn_dcm, spawn_nrk, spawn_shmem_server,
    wait_for_client_termination, CLIENT_BUILD_DELAY, SHMEM_PATH, SHMEM_SIZE,
};
use testutils::runner_args::{check_for_successful_exit, wait_for_sigterm, RunnerArgs};

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_fxmark_benchmark() {
    rackscale_fxmark_benchmark(true);
}

#[ignore]
#[test]
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
    let benchmarks = vec!["mixX0", "mixX10", "mixX100"];
    //let benchmarks = vec!["mixX10"];
    let num_microbenchs = benchmarks.len() as u64;

    let file_name = if is_shmem {
        "rackscale_shmem_fxmark_benchmark.csv"
    } else {
        "rackscale_ethernet_fxmark_benchmark.csv"
    };
    let _ignore = std::fs::remove_file(file_name);

    let build = Arc::new({
        let mut build = BuildArgs::default()
            .module("init")
            .user_feature("fxmark")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release();
        if cfg!(feature = "smoke") {
            build = build.user_feature("smoke");
        }
        build.build()
    });

    // TODO(rackscale): assert that there are enough threads/nodes on the machine for these settings?
    let _machine = Machine::determine();
    let threads = [1, 2, 4];
    let max_cores = *threads.iter().max().unwrap();
    // let num_clients = [1, 2, 4];
    let num_clients = [1];
    let max_clients = *num_clients.iter().max().unwrap();

    fn open_files(benchmark: &str, max_cores: usize, nodes: usize) -> Vec<usize> {
        if benchmark.contains("mix") {
            if cfg!(feature = "smoke") {
                vec![1]
            } else {
                if max_cores / nodes == 1 {
                    vec![1]
                } else {
                    vec![1, max_cores / nodes]
                }
            }
        } else {
            vec![0]
        }
    }

    for benchmark in benchmarks {
        for nclients in num_clients {
            setup_network(nclients + 1);

            // TODO(rackscale): probably scale with nclients?
            let shmem_size = SHMEM_SIZE;

            // TODO(rackscale, correctness): assuming here that nclient == max num nodes
            // e.g., that there is at most 1 node per client
            let open_files: Vec<usize> =
                open_files(benchmark, max_cores * max_clients, max_clients);

            for &cores in threads.iter() {
                let timeout =
                    num_microbenchs * (90_000 + cores as u64 * 20000 + nclients as u64 * 10000);

                for &of in open_files.iter() {
                    let (tx, rx) = channel();

                    let mut shmem_server = spawn_shmem_server(SHMEM_PATH, shmem_size)
                        .expect("Failed to start shmem server");
                    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

                    let kernel_cmdline = format!(
                        "mode=client transport={} initargs={}X{}X{}",
                        if is_shmem { "shmem" } else { "ethernet" },
                        cores,
                        of,
                        benchmark
                    );

                    let controller_cmdline = format!(
                        "mode=controller transport={}",
                        if is_shmem { "shmem" } else { "ethernet" }
                    );

                    // Create controller
                    let build1 = build.clone();
                    let controller = std::thread::spawn(move || {
                        let mut cmdline_controller =
                            RunnerArgs::new_with_build("userspace-smp", &build1)
                                .timeout(timeout)
                                .cmd(&controller_cmdline)
                                .shmem_size(shmem_size as usize)
                                .shmem_path(SHMEM_PATH)
                                .tap("tap0")
                                .no_network_setup()
                                .workers(2)
                                .use_vmxnet3();
                        //.setaffinity()

                        if cfg!(feature = "smoke") {
                            cmdline_controller = cmdline_controller.memory(8192);
                        } else {
                            cmdline_controller =
                                cmdline_controller.memory(core::cmp::max(73728, cores * 2048));
                        }
                        //cmdline_controller = cmdline_controller.nodes(0);

                        let output = String::new();
                        let qemu_run = || -> Result<WaitStatus> {
                            let mut p = spawn_nrk(&cmdline_controller)?;

                            let _ = wait_for_client_termination::<()>(&rx);
                            p.process.kill(SIGTERM)
                        };
                        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
                    });

                    // TODO(rackscale): add loop for nclients
                    let build2 = build.clone();
                    let client = std::thread::spawn(move || {
                        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
                        let mut cmdline_client =
                            RunnerArgs::new_with_build("userspace-smp", &build2)
                                .timeout(timeout)
                                .shmem_size(shmem_size as usize)
                                .shmem_path(SHMEM_PATH)
                                .tap("tap2")
                                .no_network_setup()
                                .workers(2)
                                .cores(max_cores)
                                .use_vmxnet3()
                                .cmd(kernel_cmdline.as_str());
                        //.setaffinity()

                        if cfg!(feature = "smoke") {
                            cmdline_client = cmdline_client.memory(8192);
                        } else {
                            cmdline_client =
                                cmdline_client.memory(core::cmp::max(73728, cores * 2048));
                        }

                        /*
                        if cfg!(feature = "smoke") && cores > 2 {
                            cmdline_client = cmdline_client.nodes(2);
                        } else {
                            cmdline_client = cmdline_client.nodes(machine.max_numa_nodes());
                        }
                        */

                        let mut output = String::new();
                        let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
                            let mut p = spawn_nrk(&cmdline_client)?;

                            // Parse lines like
                            // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                            // write them to a CSV file
                            let expected_lines = if cfg!(feature = "smoke") {
                                1
                            } else {
                                cores * 10
                            };

                            // TODO(rackscale): for prep for multiclients, move to controller.
                            // TODO(rackscale): need to output num clients
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
                                    // TODO(rackscale): need to output num clients
                                    let row = "git_rev,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
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
                            notify_controller_of_termination(&tx);
                            p.process.exit()
                        };
                        check_for_successful_exit(&cmdline_client, qemu_run(cores), output);
                    });

                    let controller_ret = controller.join();
                    let client_ret = client.join();

                    let _ignore = shmem_server.send_control('c');
                    let _ignore = dcm.send_control('c');

                    client_ret.unwrap();
                    controller_ret.unwrap();
                }
            }
        }
    }
}
