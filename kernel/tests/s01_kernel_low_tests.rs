// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s01_*`: Low level kernel services: SSE, memory allocation etc.

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;

use testutils::builder::BuildArgs;
use testutils::helpers::spawn_nrk;
use testutils::runner_args::{check_for_exit, check_for_successful_exit, RunnerArgs};
use testutils::ExitStatus;

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn s01_pfault() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("pfault", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] Page Fault")?;
        p.exp_regex("Backtrace:")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(ExitStatus::PageFault, &cmdline, qemu_run(), output);
}

/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
#[test]
fn s01_gpfault() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("gpfault", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #1  - 0x[0-9a-fA-F]+")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(
        ExitStatus::GeneralProtectionFault,
        &cmdline,
        qemu_run(),
        output,
    );
}

/// Make sure the double-fault handler works as expected.
///
/// Also the test verifies that we use a separate stack for
/// faults that can always happen unexpected.
#[test]
fn s01_double_fault() {
    let build = BuildArgs::default()
        .kernel_feature("cause-double-fault")
        .build();
    let cmdline = RunnerArgs::new_with_build("double-fault", &build).qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] Double Fault")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(ExitStatus::UnrecoverableError, &cmdline, qemu_run(), output);
}

/// Make sure we can do kernel memory allocations.
///
/// This smoke tests the physical memory allocator
/// and the global allocator integration.
#[test]
fn s01_alloc() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("alloc", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string("small allocations work.")?.as_str();
        output += p.exp_string("large allocations work.")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that makes use of SSE in kernel-space and see if it works.AsMut
///
/// Tests that we have correctly set-up the hardware to deal with floating
/// point.
#[test]
fn s01_sse() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("sse", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("division = 4.566210045662101")?;
        p.exp_string("division by zero = inf")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

#[test]
fn s01_time() {
    eprintln!("Doing a release build, this might take a while...");
    let build = BuildArgs::default().release().build();
    let cmdline = RunnerArgs::new_with_build("time", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

#[test]
fn s01_timer() {
    let build = BuildArgs::default().kernel_feature("test-timer").build();
    let cmdline = RunnerArgs::new_with_build("timer", &build);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string("Setting the timer")?.as_str();
        output += p.exp_string("Got a timer interrupt")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}
