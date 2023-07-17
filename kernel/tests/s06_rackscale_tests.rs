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
use rexpect::session::PtySession;

use testutils::builder::{BuildArgs, Machine};
use testutils::runner_args::RackscaleTransport;

use testutils::rackscale_runner::{rackscale_runner, RackscaleRunState};

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_smoke_test() {
    rackscale_userspace_smoke_test(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_userspace_smoke_test() {
    rackscale_userspace_smoke_test(RackscaleTransport::Ethernet);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_smoke_test(transport: RackscaleTransport) {
    let built = BuildArgs::default()
        .module("init")
        .user_features(&[
            "test-print",
            "test-map",
            "test-alloc",
            "test-upcall",
            "test-scheduler",
            "test-syscalls",
        ])
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("print_test OK")?.as_str();
        *output += proc.exp_string("upcall_test OK")?.as_str();
        *output += proc.exp_string("map_test OK")?.as_str();
        *output += proc.exp_string("alloc_test OK")?.as_str();
        *output += proc.exp_string("scheduler_test OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.transport = transport;
    test_run.wait_for_client = true;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_phys_alloc_test() {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-phys-alloc")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("phys_alloc_test OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.wait_for_client = true;
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_test() {
    rackscale_fs_test(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_fs_test() {
    rackscale_fs_test(RackscaleTransport::Ethernet);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_fs_test(transport: RackscaleTransport) {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-fs")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("fs_test OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.transport = transport;
    test_run.wait_for_client = true;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_fs_prop_test() {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-fs-prop")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("fs_prop_test OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.wait_for_client = true;
    test_run.client_timeout = 300_000;
    test_run.controller_timeout = 300_000;
    test_run.shmem_size = test_run.shmem_size * 2;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_shootdown_test() {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-rackscale-shootdown")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn controller_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("rackscale_shootdown_test OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.controller_match_function = controller_match_function;
    test_run.client_timeout = 120_000;
    test_run.controller_timeout = 120_000;
    test_run.num_clients = 2;
    test_run.cores_per_client = 2;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_multicore_test() {
    rackscale_userspace_multicore_test(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_userspace_multicore_test() {
    rackscale_userspace_multicore_test(RackscaleTransport::Ethernet);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_multicore_test(transport: RackscaleTransport) {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-scheduler-smp")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        for _i in 0..cores_per_client {
            let r = proc.exp_regex(r#"init: Hello from core (\d+)"#)?;
            *output += r.0.as_str();
            *output += r.1.as_str();
        }
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.transport = transport;
    let machine = Machine::determine();
    test_run.cores_per_client = core::cmp::min(4, (machine.max_cores() - 1) / 2);
    test_run.wait_for_client = true;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_ethernet_userspace_multicore_multiclient() {
    rackscale_userspace_multicore_multiclient(RackscaleTransport::Ethernet);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_multicore_multiclient() {
    rackscale_userspace_multicore_multiclient(RackscaleTransport::Shmem);
}

#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_multicore_multiclient(transport: RackscaleTransport) {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-scheduler-smp")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn controller_match_function(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        num_clients: usize,
    ) -> Result<()> {
        for _i in 0..(cores_per_client * num_clients) {
            let r = proc.exp_regex(r#"init: Hello from core (\d+)"#)?;
            *output += r.0.as_str();
            *output += r.1.as_str();
        }
        Ok(())
    }

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        for _i in 0..cores_per_client {
            let r = proc.exp_regex(r#"init: Hello from core (\d+)"#)?;
            *output += r.0.as_str();
            *output += r.1.as_str();
        }
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.controller_match_function = controller_match_function;
    test_run.client_match_function = client_match_function;
    test_run.transport = transport;
    test_run.client_timeout = 120_000;
    test_run.controller_timeout = 120_000;
    let machine = Machine::determine();
    test_run.cores_per_client = core::cmp::min(4, (machine.max_cores() - 1) / 2);
    test_run.num_clients = 2;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_shmem_userspace_rumprt_fs() {
    rackscale_userspace_rumprt_fs(RackscaleTransport::Shmem);
}

/// Tests the rump FS.
///
/// Checks that we can initialize a BSD libOS and run FS operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
#[cfg(not(feature = "baremetal"))]
fn rackscale_userspace_rumprt_fs(transport: RackscaleTransport) {
    let built = BuildArgs::default()
        .module("init")
        .user_feature("test-rump-tmpfs")
        .user_feature("rumprt")
        .kernel_feature("rackscale")
        .release()
        .build();

    fn client_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("bytes_written: 12")?.as_str();
        *output += proc.exp_string("bytes_read: 12")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace".to_string(), built);
    test_run.client_match_function = client_match_function;
    test_run.wait_for_client = true;
    test_run.transport = transport;
    test_run.client_timeout = 120_000;
    test_run.controller_timeout = 120_000;

    rackscale_runner(test_run);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_rackscale_controller_shmem_alloc() {
    let built = BuildArgs::default()
        .module("init")
        .kernel_feature("rackscale")
        .kernel_feature("test-controller-shmem-alloc")
        .release()
        .build();

    fn controller_match_function(
        proc: &mut PtySession,
        output: &mut String,
        _cores_per_client: usize,
        _num_clients: usize,
    ) -> Result<()> {
        *output += proc.exp_string("controller_shmem_alloc OK")?.as_str();
        Ok(())
    }

    let mut test_run = RackscaleRunState::new("userspace-smp".to_string(), built);
    test_run.controller_match_function = controller_match_function;
    test_run.num_clients = 2;
    test_run.cores_per_client = 2;
    test_run.client_timeout = 120_000;
    test_run.controller_timeout = 120_000;

    rackscale_runner(test_run);
}
