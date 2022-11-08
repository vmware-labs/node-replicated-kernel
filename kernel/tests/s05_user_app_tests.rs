// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s05_*`: User-space applications

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;

use testutils::builder::BuildArgs;
use testutils::helpers::{setup_network, spawn_dhcpd, spawn_nc, spawn_nrk, DHCP_ACK_MATCH};
use testutils::redis::{REDIS_BENCHMARK, REDIS_PORT, REDIS_START_MATCH};
use testutils::runner_args::{wait_for_sigterm, RunnerArgs};

/// Tests that user-space application redis is functional
/// by spawing it and connecting to it from the network.
///
/// This tests various user-space components such as:
///  * Build and linking of user-space libraries
///  * BSD libOS network stack, libc and pthreads
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
///  * (kernel memfs eventually for DB persistence)
//#[cfg(not(feature = "baremetal"))]
//#[test]
#[allow(unused)]
fn s05_redis_smoke() {
    let _r = which::which(REDIS_BENCHMARK)
        .expect("redis-benchmark not installed on host, test will fail!");

    setup_network(1);

    let build = BuildArgs::default()
        .module("rkapps")
        .user_feature("rkapps:redis")
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build)
        .cmd("init=redis.bin")
        .timeout(20_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut p = spawn_nrk(&cmdline)?;

        // Test that DHCP works:
        dhcp_server.exp_regex(DHCP_ACK_MATCH)?;
        output += p.exp_string(REDIS_START_MATCH)?.as_str();

        std::thread::sleep(std::time::Duration::from_secs(6));

        let mut redis_client = spawn_nc(REDIS_PORT)?;
        // Test that redis commands work as expected:
        redis_client.send_line("ping")?;
        redis_client.exp_string("+PONG")?;
        redis_client.send_line("set msg \"Hello, World!\"")?;
        redis_client.exp_string("+OK")?;
        redis_client.send_line("get msg")?;
        redis_client.exp_string("$13")?;
        redis_client.exp_string("Hello, World!")?;

        // We can get the key--value pair with a second client too:
        let mut redis_client2 = spawn_nc(REDIS_PORT)?;
        redis_client2.send_line("get msg")?;
        redis_client2.exp_string("$13")?;
        redis_client2.exp_string("Hello, World!")?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}
