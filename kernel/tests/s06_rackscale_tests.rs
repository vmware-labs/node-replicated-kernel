// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s06_*`: Rackscale (distributed) tests
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
    check_for_successful_exit, check_for_successful_exit_no_log, log_qemu_out_with_name,
    wait_for_sigterm_or_successful_exit_no_log, RunnerArgs,
};

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_smoke_test() {
    rackscale_userspace_smoke_test(true);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_userspace_smoke_test() {
    rackscale_userspace_smoke_test(false);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_smoke_test(is_shmem: bool) {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 60_000;

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    setup_network(2);

    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    // Create build for both controller and client
    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_features(&[
                "test-print",
                "test-map",
                "test-alloc",
                "test-upcall",
                "test-scheduler",
                "test-syscalls",
            ])
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    // Run DCM and controller in separate thread
    let controller_output_array = all_outputs.clone();
    let build1 = build.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let controller_cmd = if is_shmem {
                "mode=controller transport=shmem"
            } else {
                "mode=controller transport=ethernet"
            };
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd(controller_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(2)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                // wait until all the client is done
                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to start");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client_output_array = all_outputs.clone();
    let build2 = build.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let client_cmd = if is_shmem {
                "mode=client transport=shmem"
            } else {
                "mode=client transport=ethernet"
            };
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(timeout)
                .cmd(client_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap2")
                .no_network_setup()
                .workers(2)
                .cores(1)
                .nobuild()
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;
                output += p.exp_string("print_test OK")?.as_str();
                output += p.exp_string("upcall_test OK")?.as_str();
                output += p.exp_string("map_test OK")?.as_str();
                output += p.exp_string("alloc_test OK")?.as_str();
                output += p.exp_string("scheduler_test OK")?.as_str();
                output += p.exp_eof()?.as_str();

                // notify controller we are done
                notify_controller_of_termination(&tx);

                p.process.exit()
            };
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex for output array")
                .push((String::from("Client"), output.clone()));
            check_for_successful_exit_no_log(&cmdline_client, ret, String::from("Client"));
        })
        .expect("Client thread failed to start");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    if controller_ret.is_err() || client_ret.is_err() {
        let outputs = all_outputs
            .lock()
            .expect("Failed to get mutex to output array");
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_phys_alloc_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;

    setup_network(2);

    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-phys-alloc")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let controller_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build1 = build.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd("mode=controller")
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .workers(2)
                .tap("tap0")
                .no_network_setup()
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    let client_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build2 = build.clone();
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(180_000)
                .cmd("mode=client")
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
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
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client"), output.clone()));
            check_for_successful_exit_no_log(&cmdline_client, ret, String::from("Client"));
        })
        .expect("Client thread failed to spawn");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = dcm.process.kill(SIGKILL);
    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');

    // If there's been an error, print everything
    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    assert!(outputs.len() == 2);
    if controller_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

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

    let timeout = 60_000;

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    setup_network(2);

    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

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
    let controller_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build1 = build.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let controller_cmd = if is_shmem {
                "mode=controller transport=shmem"
            } else {
                "mode=controller transport=ethernet"
            };
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd(controller_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(2)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client_output_array = all_outputs.clone();
    let build2 = build.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let client_cmd = if is_shmem {
                "mode=client transport=shmem"
            } else {
                "mode=client transport=ethernet"
            };
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(timeout)
                .cmd(client_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
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
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client"), output.clone()));
            check_for_successful_exit_no_log(&cmdline_client, ret, String::from("Client"));
        })
        .expect("Client thread failed to spawn");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    assert!(outputs.len() == 2);
    if controller_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_prop_test() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 300_000;
    let shmem_size = SHMEM_SIZE * 2;

    setup_network(2);

    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, shmem_size, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, shmem_size, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-fs-prop")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let controller_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build1 = build.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd("mode=controller")
                .shmem_size(vec![shmem_size as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(2)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    let client_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build2 = build.clone();
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(timeout)
                .cmd("mode=client")
                .shmem_size(vec![shmem_size as usize; 2])
                .shmem_path(shmem_sockets)
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
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client"), output.clone()));
            check_for_successful_exit_no_log(&cmdline_client, ret, String::from("Client"));
        })
        .expect("Client thread failed to spawn");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    assert!(outputs.len() == 2);
    if controller_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

    client_ret.unwrap();
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

    let mut shmem_servers = Vec::new();
    let mut shmem_sockets = Vec::new();
    for i in 0..(clients + 1) {
        let (shmem_socket, shmem_file) = get_shmem_names(Some(i), false);
        let shmem_server = spawn_shmem_server(&shmem_socket, &shmem_file, SHMEM_SIZE, None)
            .expect("Failed to start shmem server");
        shmem_servers.push(shmem_server);
        shmem_sockets.push(shmem_socket);
    }

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    let rx_mut = Arc::new(Mutex::new(rx));

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .user_feature("test-rackscale-shootdown")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .release()
            .build(),
    );

    let controller_output_array = all_outputs.clone();
    let controller_build = build.clone();
    let my_shmem_sockets = shmem_sockets.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
                .timeout(timeout)
                .cmd("mode=controller transport=shmem")
                .shmem_size(vec![SHMEM_SIZE as usize; clients + 1])
                .shmem_path(my_shmem_sockets)
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
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    for i in 0..clients {
        let tap = format!("tap{}", 2 * (i + 1));
        let client_build = build.clone();
        let my_shmem_sockets = shmem_sockets.clone();
        let my_rx_mut = rx_mut.clone();
        let my_output_array = all_outputs.clone();
        let client = std::thread::Builder::new()
            .name(format!("Client{}", i + 1))
            .spawn(move || {
                sleep(Duration::from_millis((i + 1) as u64 * CLIENT_BUILD_DELAY));
                let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client_build)
                    .timeout(timeout)
                    .cmd("mode=client transport=shmem")
                    .shmem_size(vec![SHMEM_SIZE as usize; clients + 1])
                    .shmem_path(my_shmem_sockets)
                    .tap(&tap)
                    .no_network_setup()
                    .workers(clients + 1)
                    .nobuild()
                    .cores(cores)
                    .use_vmxnet3();

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;

                    // Wait for the shootdown client to complete
                    let rx = my_rx_mut.lock().expect("Failed to unwrap rx mutex");
                    wait_for_client_termination::<()>(&rx);

                    let ret = p.process.kill(SIGTERM);
                    output += p.exp_eof()?.as_str();
                    ret
                };
                // Could exit with 'success' or from sigterm, depending on number of clients.
                let ret = qemu_run();
                my_output_array
                    .lock()
                    .expect("Failed to get mutex to output array")
                    .push((format!("Client{}", i + 1), output));
                wait_for_sigterm_or_successful_exit_no_log(
                    &cmdline_client,
                    ret,
                    format!("Client{}", i + 1),
                );
            })
            .expect(&format!("Client{} thread failed", i + 1));
        processes.push(client);
    }

    let mut client_rets = Vec::with_capacity(clients);
    for p in processes {
        client_rets.push(p.join());
    }
    let controller_ret = controller.join();

    for shmem_server in shmem_servers.iter_mut() {
        let _ignore = shmem_server.send_control('c');
    }
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    if controller_ret.is_err() || (&client_rets).into_iter().any(|ret| ret.is_err()) {
        let outputs = all_outputs
            .lock()
            .expect("Failed to extract output strings");
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

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
    let client_num_cores: usize = core::cmp::min(4, (machine.max_cores() - 1) / 2);

    let (tx, rx) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    setup_network(2);

    // Setup ivshmem
    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

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
    let controller_output_array = all_outputs.clone();
    let build1 = build.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let controller_cmd = if is_shmem {
                "mode=controller transport=shmem"
            } else {
                "mode=controller transport=ethernet"
            };
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &build1)
                .timeout(timeout)
                .cmd(controller_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(2)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build2 = build.clone();
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let client_cmd = if is_shmem {
                "mode=client transport=shmem"
            } else {
                "mode=client transport=ethernet"
            };
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(timeout)
                .cmd(client_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
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

                for _i in 0..client_num_cores {
                    let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
                    output += r.0.as_str();
                    output += r.1.as_str();
                }
                notify_controller_of_termination(&tx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            // Could exit with 'success' or from sigterm, depending on number of clients.
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client"), output));
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_client,
                ret,
                String::from("Client"),
            );
        })
        .expect("Client thread failed to spawn");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    if controller_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_multicore_multiclient() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;
    let machine = Machine::determine();
    let cores_per_client: usize = core::cmp::min(4, (machine.max_cores() - 1) / 2);

    setup_network(3);
    let (tx1, rx1) = channel();
    let (tx2, rx2) = channel();
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let (shmem_socket2, shmem_file2) = get_shmem_names(Some(2), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");
    let mut shmem_server2 = spawn_shmem_server(&shmem_socket2, &shmem_file2, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

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
    let controller_output_array = all_outputs.clone();
    let controller_build = build.clone();
    let shmem_sockets = vec![
        shmem_socket0.clone(),
        shmem_socket1.clone(),
        shmem_socket2.clone(),
    ];
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
                .timeout(timeout)
                .cmd("mode=controller transport=shmem")
                .shmem_size(vec![SHMEM_SIZE as usize; 3])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(3)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                for _i in 0..(cores_per_client * 2) {
                    let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
                    output += r.0.as_str();
                    output += r.1.as_str();
                }

                // Notify each client it's okay to shutdown
                notify_controller_of_termination(&tx1);
                notify_controller_of_termination(&tx2);

                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client1_output_array = all_outputs.clone();
    let client1_build = build.clone();
    let shmem_sockets = vec![
        shmem_socket0.clone(),
        shmem_socket1.clone(),
        shmem_socket2.clone(),
    ];
    let client = std::thread::Builder::new()
        .name("Client1".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client1_build)
                .timeout(timeout)
                .cmd("mode=client transport=shmem")
                .shmem_size(vec![SHMEM_SIZE as usize; 3])
                .shmem_path(shmem_sockets)
                .tap("tap2")
                .no_network_setup()
                .workers(3)
                .cores(cores_per_client)
                .memory(4096)
                .nobuild() // Use single build for all for consistency
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;

                for _i in 0..cores_per_client {
                    let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
                    output += r.0.as_str();
                    output += r.1.as_str();
                }

                // Wait for controller to terminate
                let _ = wait_for_client_termination::<()>(&rx1);

                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            // Could exit with 'success' or from sigterm, depending on number of clients.
            let ret = qemu_run();
            client1_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client1"), output));
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_client,
                ret,
                String::from("Client1"),
            );
        })
        .expect("Client1 thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client2_output_array = all_outputs.clone();
    let client2_build = build.clone();
    let shmem_sockets = vec![
        shmem_socket0.clone(),
        shmem_socket1.clone(),
        shmem_socket2.clone(),
    ];
    let client2 = std::thread::Builder::new()
        .name("Client2".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY * 2));
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client2_build)
                .timeout(timeout)
                .cmd("mode=client transport=shmem")
                .shmem_size(vec![SHMEM_SIZE as usize; 3])
                .shmem_path(shmem_sockets)
                .tap("tap4")
                .no_network_setup()
                .workers(3)
                .cores(cores_per_client)
                .memory(4096)
                .nobuild() // Use build from previous client for consistency
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_client)?;

                for _i in 0..cores_per_client {
                    let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
                    output += r.0.as_str();
                    output += r.1.as_str();
                }

                // Wait for controller to terminate
                let _ = wait_for_client_termination::<()>(&rx2);

                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            // Could exit with 'success' or from sigterm, depending on number of clients.
            let ret = qemu_run();
            client2_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client2"), output));
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_client,
                ret,
                String::from("Client2"),
            );
        })
        .expect("Client2 thread failed to spawn");

    let client2_ret = client2.join();
    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = shmem_server2.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    if controller_ret.is_err() || client2_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

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
    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    setup_network(2);

    // Setup ivshmem file
    let (shmem_socket0, shmem_file0) = get_shmem_names(Some(0), false);
    let (shmem_socket1, shmem_file1) = get_shmem_names(Some(1), false);
    let mut shmem_server0 = spawn_shmem_server(&shmem_socket0, &shmem_file0, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 0");
    let mut shmem_server1 = spawn_shmem_server(&shmem_socket1, &shmem_file1, SHMEM_SIZE, None)
        .expect("Failed to start shmem server 1");

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

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
    let controller_output_array = all_outputs.clone();
    let build1 = build.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let controller_cmd = if is_shmem {
                "mode=controller transport=shmem"
            } else {
                "mode=controller transport=ethernet"
            };
            let cmdline_controller = RunnerArgs::new_with_build("userspace", &build1)
                .timeout(timeout)
                .cmd(controller_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(2)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                let _ = wait_for_client_termination::<()>(&rx);
                let ret = p.process.kill(SIGTERM);
                output += p.exp_eof()?.as_str();
                ret
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let client_output_array = all_outputs.clone();
    let shmem_sockets = vec![shmem_socket0.clone(), shmem_socket1.clone()];
    let build2 = build.clone();
    let client = std::thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            sleep(Duration::from_millis(CLIENT_BUILD_DELAY));
            let client_cmd = if is_shmem {
                "mode=client transport=shmem"
            } else {
                "mode=client transport=ethernet"
            };
            let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &build2)
                .timeout(timeout)
                .cmd(client_cmd)
                .shmem_size(vec![SHMEM_SIZE as usize; 2])
                .shmem_path(shmem_sockets)
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
            let ret = qemu_run();
            client_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Client"), output.clone()));
            check_for_successful_exit_no_log(&cmdline_client, ret, String::from("Client"));
        })
        .expect("Client thread failed to start");

    let client_ret = client.join();
    let controller_ret = controller.join();

    let _ignore = shmem_server0.send_control('c');
    let _ignore = shmem_server1.send_control('c');
    let _ignore = dcm.process.kill(SIGKILL);

    let outputs = all_outputs
        .lock()
        .expect("Failed to get mutex to output array");
    if controller_ret.is_err() || client_ret.is_err() {
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
    }

    client_ret.unwrap();
    controller_ret.unwrap();
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_controller_shmem_alloc() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let timeout = 120_000;
    let clients = 2;
    let mut processes = Vec::with_capacity(clients);
    let cores = 2;

    setup_network(clients + 1);

    let mut shmem_servers = Vec::new();
    let mut shmem_sockets = Vec::new();
    for i in 0..(clients + 1) {
        let (shmem_socket, shmem_file) = get_shmem_names(Some(i), false);
        let shmem_server = spawn_shmem_server(&shmem_socket, &shmem_file, SHMEM_SIZE, None)
            .expect("Failed to start shmem server");
        shmem_servers.push(shmem_server);
        shmem_sockets.push(shmem_socket);
    }

    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    let (tx, rx) = channel();
    let rx_mut = Arc::new(Mutex::new(rx));

    let build = Arc::new(
        BuildArgs::default()
            .module("init")
            .kernel_feature("shmem")
            .kernel_feature("ethernet")
            .kernel_feature("rackscale")
            .kernel_feature("test-controller-shmem-alloc")
            .release()
            .build(),
    );

    let controller_build = build.clone();
    let my_shmem_sockets = shmem_sockets.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller = RunnerArgs::new_with_build("userspace-smp", &controller_build)
                .timeout(timeout)
                .cmd("mode=controller transport=shmem")
                .shmem_size(vec![SHMEM_SIZE as usize; clients + 1])
                .shmem_path(my_shmem_sockets)
                .tap("tap0")
                .no_network_setup()
                .workers(clients + 1)
                .use_vmxnet3();

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;
                output += p.exp_string("controller_shmem_alloc OK")?.as_str();
                output += p.exp_eof()?.as_str();

                // Notify clients all are done.
                for _i in 0..clients {
                    notify_controller_of_termination(&tx);
                }
                p.process.exit()
            };
            // This will only find sigterm, that's okay
            check_for_successful_exit(&cmdline_controller, qemu_run(), output);
        })
        .expect("Controller thread failed to spawn");

    for i in 0..clients {
        let tap = format!("tap{}", 2 * (i + 1));
        let client_build = build.clone();
        let my_shmem_sockets = shmem_sockets.clone();
        let my_rx_mut = rx_mut.clone();
        let client = std::thread::Builder::new()
            .name(format!("Client{}", i + 1))
            .spawn(move || {
                sleep(Duration::from_millis((i + 1) as u64 * CLIENT_BUILD_DELAY));
                let cmdline_client = RunnerArgs::new_with_build("userspace-smp", &client_build)
                    .timeout(timeout)
                    .cmd("mode=client transport=shmem")
                    .shmem_size(vec![SHMEM_SIZE as usize; clients + 1])
                    .shmem_path(my_shmem_sockets)
                    .tap(&tap)
                    .no_network_setup()
                    .workers(clients + 1)
                    .nobuild()
                    .cores(cores)
                    .use_vmxnet3();

                let qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;

                    // Wait for the shootdown client to complete
                    let rx = my_rx_mut.lock().expect("Failed to unwrap rx mutex");
                    wait_for_client_termination::<()>(&rx);

                    let ret = p.process.kill(SIGTERM);
                    let _ = p.exp_eof()?.as_str();
                    ret
                };
                // Could exit with 'success' or from sigterm, depending on number of clients.
                let ret = qemu_run();
                wait_for_sigterm_or_successful_exit_no_log(
                    &cmdline_client,
                    ret,
                    format!("Client{}", i + 1),
                );
            })
            .expect(&format!("Client{} thread failed", i + 1));
        processes.push(client);
    }

    let mut client_rets = Vec::with_capacity(clients);
    for p in processes {
        client_rets.push(p.join());
    }
    let controller_ret = controller.join();

    for shmem_server in shmem_servers.iter_mut() {
        let _ignore = shmem_server.send_control('c');
    }
    let _ignore = dcm.process.kill(SIGKILL);

    for ret in client_rets {
        ret.unwrap();
    }
    controller_ret.unwrap();
}
