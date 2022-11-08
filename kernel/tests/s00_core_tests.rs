// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s00_*`: Core kernel functionality like boot-up and fault handling

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;

use testutils::builder::BuildArgs;
use testutils::helpers::spawn_nrk;
use testutils::runner_args::{check_for_exit, check_for_successful_exit, RunnerArgs};
use testutils::ExitStatus;

/// Make sure exiting the kernel works.
///
/// We have a special ioport that we use to signal the exit to
/// qemu and some parsing logic to read the exit code
/// and communicate if our tests passed or failed.
#[test]
fn s00_exit() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("exit", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("Started")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Make sure the page-fault handler works as expected  -- even if
/// we're early on in initialization.
/// In essence a trap should be raised but we can't get a backtrace yet
/// since we don't have memory allocation.
#[test]
fn s00_pfault_early() {
    let build = BuildArgs::default()
        .kernel_feature("cause-pfault-early")
        .build();
    let cmdline = RunnerArgs::new_with_build("pfault-early", &build).qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] Early Page Fault")?;
        p.exp_string("Faulting address: 0x4000deadbeef")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(
        ExitStatus::ExceptionDuringInitialization,
        &cmdline,
        qemu_run(),
        output,
    );
}

/// Make sure the general-protection-fault handler works as expected  -- even if
/// we're early on in initialization.
/// In essence a trap should be raised but we can't get a backtrace yet
/// since we don't have memory allocation.
#[test]
fn s00_gpfault_early() {
    let build = BuildArgs::default()
        .kernel_feature("cause-gpfault-early")
        .build();
    let cmdline = RunnerArgs::new_with_build("gpfault-early", &build).qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] Early General Protection Fault")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(
        ExitStatus::ExceptionDuringInitialization,
        &cmdline,
        qemu_run(),
        output,
    );
}
