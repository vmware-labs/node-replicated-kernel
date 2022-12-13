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
use rexpect::process::wait::WaitStatus;

use testutils::builder::BuildArgs;
use testutils::helpers::{
    setup_network, spawn_dcm, spawn_nrk, spawn_shmem_server, SHMEM_PATH, SHMEM_SIZE,
};
use testutils::runner_args::{check_for_successful_exit, RunnerArgs};

#[test]
#[cfg(not(feature = "baremetal"))]
fn s11_rackscale_shmem_fxmark_benchmark() {
    rackscale_fxmark_benchmark(true);
}

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

    let file_name = if is_shmem {
        "rackscale_shmem_fxmark_benchmark.csv"
    } else {
        "rackscale_ethernet_fxmark_benchmark.csv"
    };

    setup_network(2);
    let timeout = 180_000;

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("fxmark")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    fn open_files(benchmark: &str, max_cores: usize, nodes: usize) -> Vec<usize> {
        if benchmark.contains("mix") {
            vec![1, max_cores / nodes]
        } else {
            vec![0]
        }
    }

    let cores = 1;
    for benchmark in benchmarks {
        let open_files: Vec<usize> = open_files(benchmark, 1, 1);
        for &of in open_files.iter() {
            let mut shmem_server =
                spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");

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
                let mut cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                    .timeout(timeout)
                    .cmd(&controller_cmdline)
                    .shmem_size(SHMEM_SIZE as usize)
                    .shmem_path(SHMEM_PATH)
                    .tap("tap0")
                    .no_network_setup()
                    .workers(2)
                    .use_vmxnet3();

                if cfg!(feature = "smoke") {
                    cmdline_controller = cmdline_controller.memory(8192);
                } else {
                    cmdline_controller =
                        cmdline_controller.memory(core::cmp::max(49152, cores * 512));
                }
                cmdline_controller = cmdline_controller.nodes(0);

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut dcm = spawn_dcm(1, timeout)?;
                    let mut p = spawn_nrk(&cmdline_controller)?;
                    output += p.exp_eof()?.as_str();

                    dcm.send_control('c')?;
                    p.process.exit()
                };

                let _ignore = qemu_run();
            });

            let build2 = build.clone();
            let client = std::thread::spawn(move || {
                sleep(Duration::from_millis(15_000));
                let mut cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                    .timeout(timeout)
                    .shmem_size(SHMEM_SIZE as usize)
                    .shmem_path(SHMEM_PATH)
                    .tap("tap2")
                    .no_network_setup()
                    .workers(2)
                    .use_vmxnet3()
                    .cmd(kernel_cmdline.as_str());

                if cfg!(feature = "smoke") {
                    cmdline_client = cmdline_client.memory(8192);
                } else {
                    cmdline_client = cmdline_client.memory(core::cmp::max(49152, cores * 512));
                }
                cmdline_client = cmdline_client.nodes(0);

                // Run the client and parse results
                let mut output = String::new();

                let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;

                    // Parse lines like
                    // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                    // write them to a CSV file
                    let expected_lines = cores * 10;

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
                check_for_successful_exit(&cmdline_client, qemu_run(cores), output);
            });

            controller.join().unwrap();
            client.join().unwrap();

            let _ignore = shmem_server.send_control('c');
        }
    }
}
