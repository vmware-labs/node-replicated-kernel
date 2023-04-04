// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s06_*`: Rackscale (distributed) tests
use std::sync::mpsc::channel;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;

use spin::Mutex;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{
    notify_controller_of_termination, setup_network, spawn_dcm, spawn_nrk, spawn_shmem_server,
    wait_for_client_termination, CLIENT_BUILD_DELAY, SHMEM_PATH, SHMEM_SIZE,
};
use testutils::runner_args::{check_for_successful_exit, wait_for_sigterm, RunnerArgs};

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_phys_alloc_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;

    setup_network(2);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    let (tx, rx) = channel();

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
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .workers(2)
            .tap("tap0")
            .no_network_setup()
            .use_vmxnet3();

        let output = String::new();
        let qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            let _ = wait_for_client_termination::<()>(&rx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
            .timeout(180_000)
            .cmd("mode=client")
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .nobuild()
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("phys_alloc_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            notify_controller_of_termination(&tx);
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = dcm.send_control('c');
    let _ignore = shmem_server.send_control('c');

    client_ret.unwrap();
    controller_ret.unwrap();
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
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 30_000;

    let (tx, rx) = channel();
    setup_network(2);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

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

        let output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            let _ = wait_for_client_termination::<()>(&rx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    // Run client in separate thead. Wait a bit to make sure controller started
    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
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
            .nobuild()
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("fs_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            notify_controller_of_termination(&tx);
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_prop_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 240_000;

    setup_network(2);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    let (tx, rx) = channel();

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

        let output = String::new();
        let qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            let _ = wait_for_client_termination::<()>(&rx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
            .timeout(timeout)
            .cmd("mode=client")
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(2)
            .nobuild()
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            output += p.exp_string("fs_prop_test OK")?.as_str();
            output += p.exp_eof()?.as_str();
            notify_controller_of_termination(&tx);
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_multiinstance() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 60_000;
    let clients = 3;
    let mut processes = Vec::with_capacity(clients);

    setup_network(clients + 1);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    let (tx, rx) = channel();
    let tx_mut = Arc::new(Mutex::new(tx));

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
            .shmem_size(SHMEM_SIZE)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(clients + 1)
            .use_vmxnet3();

        let output = String::new();
        let qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            for _i in 0..clients {
                let _ = wait_for_client_termination::<()>(&rx);
            }
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    for i in 1..=clients {
        let tap = format!("tap{}", 2 * i);
        let client_build = build.clone();
        let my_tx_mut = tx_mut.clone();
        let client = std::thread::spawn(move || {
            sleep(Duration::from_millis(i as u64 * CLIENT_BUILD_DELAY));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client_build)
                .timeout(timeout)
                .cmd("mode=client transport=shmem")
                .shmem_size(SHMEM_SIZE)
                .shmem_path(SHMEM_PATH)
                .tap(&tap)
                .no_network_setup()
                .workers(clients + 1)
                .nobuild()
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;
                output += p.exp_string("print_test OK")?.as_str();
                output += p.exp_eof()?.as_str();
                let tx = my_tx_mut.lock();
                notify_controller_of_termination(&tx);
                p.process.exit()
            };

            check_for_successful_exit(&cmdline_client, qemu_run(), output);
        });
        processes.push(client);
    }

    let mut client_rets = Vec::with_capacity(clients);
    for p in processes {
        client_rets.push(p.join());
    }
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    for ret in client_rets {
        ret.unwrap();
    }
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_shootdown_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;
    let clients = 2;
    let mut processes = Vec::with_capacity(clients);
    let cores = 2;

    setup_network(clients + 1);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    let (tx, rx) = channel();

    let rx_mut = Arc::new(Mutex::new(rx));

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-rackscale-shootdown")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .kernel_feature("test-rackscale-shootdown")
            .release()
            .build(),
    );

    let controller_build = build.clone();
    let controller = std::thread::spawn(move || {
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
            .timeout(timeout)
            .cmd("mode=controller transport=shmem")
            .shmem_size(SHMEM_SIZE)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(clients + 1)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;
            output += p.exp_string("rackscale_shootdown_test OK")?.as_str();

            // Notify clients all are done.
            for _i in 0..clients {
                notify_controller_of_termination(&tx);
            }

            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    for i in 0..clients {
        let tap = format!("tap{}", 2 * (i + 1));
        let client_build = build.clone();
        let my_rx_mut = rx_mut.clone();
        let client = std::thread::spawn(move || {
            sleep(Duration::from_millis((i + 1) as u64 * CLIENT_BUILD_DELAY));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client_build)
                .timeout(timeout)
                .cmd("mode=client transport=shmem")
                .shmem_size(SHMEM_SIZE)
                .shmem_path(SHMEM_PATH)
                .tap(&tap)
                .no_network_setup()
                .workers(clients + 1)
                .nobuild()
                .cores(cores)
                .use_vmxnet3();

            let output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;

                // Wait for the shootdown client to complete
                let rx = my_rx_mut.lock();
                wait_for_client_termination::<()>(&rx);

                p.process.kill(SIGTERM)
            };
            wait_for_sigterm(&cmdline_client, qemu_run(), output);
        });
        processes.push(client);
    }

    let mut client_rets = Vec::with_capacity(clients);
    for p in processes {
        client_rets.push(p.join());
    }
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    for ret in client_rets {
        ret.unwrap();
    }
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_multicore_test() {
    rackscale_userspace_multicore_test(true);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_userspace_multicore_test() {
    rackscale_userspace_multicore_test(false);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_multicore_test(is_shmem: bool) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 60_000;

    let machine = Machine::determine();
    let client_num_cores: usize = core::cmp::min(5, (machine.max_cores() - 1) / 2);

    let (tx, rx) = channel();

    setup_network(2);

    // Setup ivshmem file
    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");

    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-scheduler-smp")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run controller in separate thread
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

        let output = String::new();
        let qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            let _ = wait_for_client_termination::<()>(&rx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    // Run client in separate thead. Wait a bit to make sure controller started
    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
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
            .cores(client_num_cores)
            .memory(4096)
            .nobuild()
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;

            for _i in 0..(client_num_cores - 1) {
                let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
                output += r.0.as_str();
                output += r.1.as_str();
            }
            notify_controller_of_termination(&tx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_client, qemu_run(), output);
    });

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_request_core_remote_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 180_000;

    setup_network(3);
    let (tx1, rx1) = channel();
    let (tx2, rx2) = channel();

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");

    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-request-core-remote")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run controller in separate thread
    let controller_build = build.clone();
    let controller = std::thread::spawn(move || {
        let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
            .timeout(timeout)
            .cmd("mode=controller transport=shmem")
            .shmem_size(SHMEM_SIZE)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(3)
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            // Could be in either order, so we won't specify core number
            output += p.exp_string("Hello from core")?.as_str();
            output += p.exp_string("Hello from core")?.as_str();

            // Notify each client it's okay to shutdown
            notify_controller_of_termination(&tx1);
            notify_controller_of_termination(&tx2);

            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    // Run client in separate thead. Wait a bit to make sure controller started
    let client1_build = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client1_build)
            .timeout(timeout)
            .cmd("mode=client transport=shmem")
            .shmem_size(SHMEM_SIZE)
            .shmem_path(SHMEM_PATH)
            .tap("tap2")
            .no_network_setup()
            .workers(3)
            .cores(2)
            .memory(4096)
            .nobuild() // Use single build for all for consistency
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            // Wait for controller to terminate
            let _ = wait_for_client_termination::<()>(&rx1);

            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_client, qemu_run(), output);
    });

    // Run client in separate thead. Wait a bit to make sure controller started
    let client2_build = build.clone();
    let client2 = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY * 2));
        let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client2_build)
            .timeout(timeout)
            .cmd("mode=client transport=shmem")
            .shmem_size(SHMEM_SIZE)
            .shmem_path(SHMEM_PATH)
            .tap("tap4")
            .no_network_setup()
            .workers(3)
            .cores(2)
            .memory(4096)
            .nobuild() // Use build from previous client for consistency
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;

            // Wait for controller to terminate
            let _ = wait_for_client_termination::<()>(&rx2);

            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_client, qemu_run(), output);
    });

    let client2_ret = client2.join();
    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    client2_ret.unwrap();
    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_rumprt_fs() {
    rackscale_userspace_rumprt_fs(true);
}

/// Tests the rump FS.
///
/// Checks that we can initialize a BSD libOS and run FS operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_rumprt_fs(is_shmem: bool) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;
    let (tx, rx) = channel();

    setup_network(2);

    // Setup ivshmem file
    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");
    let mut dcm = spawn_dcm(1, timeout).expect("Failed to start DCM");

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-rump-tmpfs")
            .user_feature("rumprt")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run controller in separate thread
    let build1 = build.clone();
    let controller = std::thread::spawn(move || {
        let controller_cmd = if is_shmem {
            "mode=controller transport=shmem"
        } else {
            "mode=controller transport=ethernet"
        };
        let cmdline_controller = RunnerArgs::new_with_build("userspace", &build1)
            .timeout(timeout)
            .cmd(controller_cmd)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH)
            .tap("tap0")
            .no_network_setup()
            .workers(2)
            .use_vmxnet3();

        let output = String::new();
        let qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_controller)?;

            let _ = wait_for_client_termination::<()>(&rx);
            p.process.kill(SIGTERM)
        };

        wait_for_sigterm(&cmdline_controller, qemu_run(), output);
    });

    // Run client in separate thead. Wait a bit to make sure controller started
    let build2 = build.clone();
    let client = std::thread::spawn(move || {
        sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
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
            .nobuild()
            .use_vmxnet3();

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline_client)?;
            p.exp_string("bytes_written: 12")?;
            p.exp_string("bytes_read: 12")?;
            output = p.exp_eof()?;
            notify_controller_of_termination(&tx);
            p.process.exit()
        };

        check_for_successful_exit(&cmdline_client, qemu_run(), output);
    });

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server.send_control('c');
    let _ignore = dcm.send_control('c');

    client_ret.unwrap();
    controller_ret.unwrap();
}
