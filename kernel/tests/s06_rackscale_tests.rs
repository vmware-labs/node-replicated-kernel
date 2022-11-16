// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s06_*`: Rackscale (distributed) tests

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;

use testutils::builder::BuildArgs;
use testutils::helpers::{
    setup_network, setup_shmem, spawn_dcm, spawn_nrk, SHMEM_PATH, SHMEM_SIZE,
};
use testutils::runner_args::{check_for_successful_exit, RunnerArgs};

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_phys_alloc_test() {
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let large_shmem_size = 16; // Needs to be large to have a large page
    setup_shmem(SHMEM_PATH, large_shmem_size);

    let timeout = 180_000;

    setup_network(2);

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-phys-alloc")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let build1 = build.clone();
    let controller = std::thread::spawn(move || {
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
            .timeout(timeout)
            .cmd("mode=controller")
            .shmem_size(large_shmem_size as usize)
            .shmem_path(SHMEM_PATH)
            .workers(2)
            .tap("tap0")
            .no_network_setup()
            .use_vmxnet3();

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
        sleep(Duration::from_millis(5_000));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
            .timeout(180_000)
            .cmd("mode=client")
            .shmem_size(large_shmem_size as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("phys_alloc_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    controller.join().unwrap();
    client.join().unwrap();

    let _ignore = remove_file(&SHMEM_PATH);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_test() {
    rackscale_fs_test(true);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_fs_test() {
    rackscale_fs_test(false);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_fs_test(is_shmem: bool) {
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    // Setup ivshmem file
    setup_shmem(SHMEM_PATH, SHMEM_SIZE);

    setup_network(2);
    let timeout = 30_000;

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-fs")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run DCM and controller in separate thread
    let build1 = build.clone();
    let controller = std::thread::spawn(move || {
        let controller_cmd = if is_shmem {
            "mode=controller transport=shmem"
        } else {
            "mode=controller transport=ethernet"
        };
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
            .timeout(timeout)
            .cmd(controller_cmd)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dcm = spawn_dcm(1, timeout)?;
            let mut p = spawn_nrk(&cmdline_controller)?;

            //output += p.exp_string("Finished sending requests!")?.as_str();
            output += p.exp_eof()?.as_str();

            dcm.send_control('c')?;
            p.process.exit()
        };

        let _ignore = qemu_run();
    });

    // Run client in separate thead. Wait a bit to make sure DCM and controller started
    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(5_000));
        let client_cmd = if is_shmem {
            "mode=client transport=shmem"
        } else {
            "mode=client transport=ethernet"
        };
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
            .timeout(timeout)
            .cmd(client_cmd)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("fs_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    controller.join().unwrap();
    client.join().unwrap();

    let _ignore = remove_file(SHMEM_PATH);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_dcm_test() {
    rackscale_dcm_test(true);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_dcm_test() {
    rackscale_dcm_test(false);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_dcm_test(is_shmem: bool) {
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    // Setup ivshmem file
    setup_shmem(SHMEM_PATH, SHMEM_SIZE);

    setup_network(2);
    let timeout = 30_000;

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-fs")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run DCM and controller in separate thread
    let build1 = build.clone();
    let controller = std::thread::spawn(move || {
        let controller_cmd = if is_shmem {
            "mode=controller transport=shmem"
        } else {
            "mode=controller transport=ethernet"
        };
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
            .timeout(timeout)
            .cmd(controller_cmd)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dcm = spawn_dcm(1, timeout)?;
            let mut p = spawn_nrk(&cmdline_controller)?;

            output += p.exp_string("Created DCM UDP socket!")?.as_str();
            output += p.exp_string("Created DCM RPC client!")?.as_str();
            output += p.exp_eof()?.as_str();

            dcm.send_control('c')?;
            p.process.exit()
        };

        let _ignore = qemu_run();
    });

    // Run client in separate thead. Wait a bit to make sure DCM and controller started
    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(5_000));
        let client_cmd = if is_shmem {
            "mode=client transport=shmem"
        } else {
            "mode=client transport=ethernet"
        };
        let cmdline_client = RunnerArgs::new_with_build("dcm", &build2)
            .timeout(timeout)
            .cmd(client_cmd)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("About to send resource requests")?.as_str();
            output += p
                .exp_string("Finished sending resource requests!")?
                .as_str();
            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    controller.join().unwrap();
    client.join().unwrap();

    let _ignore = remove_file(SHMEM_PATH);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_prop_test() {
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    // Setup ivshmem file
    setup_shmem(SHMEM_PATH, SHMEM_SIZE);

    setup_network(2);
    let timeout = 180_000;

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-fs-prop")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let build1 = build.clone();
    let controller = std::thread::spawn(move || {
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
            .timeout(timeout)
            .cmd("mode=controller")
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dcm = spawn_dcm(1, timeout)?;
            let mut p = spawn_nrk(&cmdline_controller)?;
            //output += p.exp_string("Finished sending requests!")?.as_str();
            output += p.exp_eof()?.as_str();

            dcm.send_control('c')?;
            p.process.exit()
        };

        let _ignore = qemu_run();
    });

    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(5_000));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
            .timeout(timeout)
            .cmd("mode=client")
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("fs_prop_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    controller.join().unwrap();
    client.join().unwrap();

    let _ignore = remove_file(SHMEM_PATH);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_multiinstance() {
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 60_000;
    let clients = 4;
    let mut processes = Vec::with_capacity(clients + 1);

    setup_shmem(SHMEM_PATH, SHMEM_SIZE);
    setup_network(clients + 1);

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-print")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let controller_build = build.clone();
    let controller = std::thread::spawn(move || {
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
            .timeout(timeout)
            .cmd("mode=controller transport=shmem")
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(clients + 1)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut dcm = spawn_dcm(1, timeout)?;
            let mut p = spawn_nrk(&cmdline_controller)?;
            //output += p.exp_string("Finished sending requests!")?.as_str();
            output += p.exp_eof()?.as_str();

            dcm.send_control('c')?;
            p.process.exit()
        };

        let _ignore = qemu_run();
    });
    processes.push(controller);

    for i in 1..=clients {
        let tap = format!("tap{}", 2 * i);
        let client_build = build.clone();
        let client = std::thread::spawn(move || {
            sleep(Duration::from_millis(i as u64 * 10_000));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client_build)
                .timeout(timeout)
                .cmd("mode=client transport=shmem")
                .shmem_size(SHMEM_SIZE as usize)
                .shmem_path(SHMEM_PATH)
                .tap(&tap)
                .no_network_setup()
                .workers(clients + 1)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;
                output += p.exp_string("print_test OK")?.as_str();
                output += p.exp_eof()?.as_str();
                p.process.exit()
            };

            check_for_successful_exit(&cmdline_client, qemu_run(), output);
        });
        processes.push(client);
    }

    for p in processes {
        p.join().unwrap();
    }

    let _ignore = remove_file(SHMEM_PATH);
}