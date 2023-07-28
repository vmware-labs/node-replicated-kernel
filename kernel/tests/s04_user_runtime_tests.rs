// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s04_*`: User-space runtimes

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;

use testutils::builder::{BuildArgs, Machine};
use testutils::helpers::{
    setup_network, spawn_dhcpd, spawn_nrk, spawn_ping, spawn_receiver, DHCP_ACK_MATCH,
};
use testutils::runner_args::{check_for_successful_exit, wait_for_sigterm, RunnerArgs};

/// Tests the lineup scheduler multi-core ability.
///
/// Makes sure we can request cores and spawn threads on said cores.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s04_userspace_multicore() {
    let machine = Machine::determine();
    let num_cores: usize = machine.max_cores();
    let build = BuildArgs::default()
        .user_feature("test-scheduler-smp")
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
        .cores(num_cores)
        .memory(4096)
        .timeout(120_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        for _i in 0..num_cores {
            let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
            output += r.0.as_str();
            output += r.1.as_str();
        }

        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

/// Tests that user-space networking is functional.
///
/// This tests various user-space components such as:
///  * BSD libOS network stack
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
#[cfg(not(feature = "baremetal"))]
#[test]
fn s04_userspace_rumprt_net() {
    setup_network(1);

    let build = BuildArgs::default()
        .user_feature("test-rump-net")
        .user_feature("rumprt")
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build)
        .timeout(20_000)
        .no_network_setup();

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut p = spawn_nrk(&cmdline)?;
        let mut receiver = spawn_receiver()?;

        // Test that DHCP works:
        output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();

        // Test that sendto works:
        // Used to swallow just the first packet (see also: https://github.com/rumpkernel/rumprun/issues/131)
        // Update: Now on NetBSD v8 it swallows the first 6-8 packets
        output += receiver.exp_string("pkt 10")?.as_str();
        output += receiver.exp_string("pkt 11")?.as_str();
        output += receiver.exp_string("pkt 12")?.as_str();

        // Test that ping works:
        let mut ping = spawn_ping()?;
        for _ in 0..3 {
            ping.exp_regex(r#"64 bytes from 172.31.0.10: icmp_seq=(\d+) ttl=255 time=(.*?ms)"#)?;
        }

        ping.process.kill(SIGTERM)?;
        dhcp_server.send_control('c')?;
        receiver.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

/// Tests the rump FS.
///
/// Checks that we can initialize a BSD libOS and run FS operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s04_userspace_rumprt_fs() {
    let build = BuildArgs::default()
        .user_feature("test-rump-tmpfs")
        .user_feature("rumprt")
        .build();
    let cmdline = &RunnerArgs::new_with_build("userspace", &build).timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(cmdline)?;
        p.exp_string("bytes_written: 12")?;
        p.exp_string("bytes_read: 12")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(cmdline, qemu_run(), output);
}

/// Tests a flurry of shootdowns for multiple threads.
/// TODO: this results in some kind of weird slowdown.
/// TODO: this test isn't fully developed yet - the conditions for success are not implemented.
///
/// Makes sure all the shootdowns are sufficiently handled.
#[ignore]
#[cfg(not(feature = "baremetal"))]
#[test]
fn s04_userspace_concurrent_shootdowns() {
    let _machine = Machine::determine();
    let num_cores: usize = 3; //machine.max_cores();
    let build = BuildArgs::default()
        .user_feature("test-concurrent-shootdown")
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace-smp", &build)
        .cores(num_cores)
        .memory(4096 * 2)
        .timeout(60_000);

    let output = String::new();
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        for _i in 0..num_cores {
            // TODO: detect success
        }

        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}
