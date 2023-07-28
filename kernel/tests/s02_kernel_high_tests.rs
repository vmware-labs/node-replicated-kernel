// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s02_*`: High level kernel services: ACPI, core booting mechanism, NR, VSpace etc.

use std::fs::File;
use std::io::Write;
use std::{io, process};

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;
use rexpect::session::PtyReplSession;
use rexpect::spawn;

use testutils::builder::BuildArgs;
use testutils::helpers::spawn_nrk;
use testutils::runner_args::{check_for_successful_exit, RunnerArgs};

/// Test that we can initialize the ACPI subsystem and figure out the machine topology.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s02_acpi_topology() {
    let build = BuildArgs::default().build();
    let cmdline = &RunnerArgs::new_with_build("acpi-topology", &build)
        .cores(80)
        .nodes(8)
        .memory(8192)
        .pmem(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(cmdline).expect("Can't spawn QEMU instance");

        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(cmdline, qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology
/// (a different one than acpi_smoke).
#[cfg(not(feature = "baremetal"))]
#[test]
fn s02_acpi_smoke() {
    let build = BuildArgs::default().build();
    let cmdline = &RunnerArgs::new_with_build("acpi-smoke", &build)
        .cores(2)
        .memory(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(cmdline).expect("Can't spawn QEMU instance");

        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(cmdline, qemu_run(), output);
}

/// Test that we can boot an additional core.
///
/// Utilizes the app core initializtion logic
/// as well as the APIC driver (sending IPIs).
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s02_coreboot_smoke() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("coreboot-smoke", &build)
        .cores(2)
        // Adding this to qemu will print register state on CPU rests (triple-faults)
        // helpful to debug core-booting related failures:
        .qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_string("Hello from the other side")?.as_str();
        output += p.exp_string("Core has started")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can multiple cores and use the node-replication log to communicate.
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s02_coreboot_nrlog() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("coreboot-nrlog", &build)
        .cores(4)
        // Adding this to qemu will print register state on CPU rests (triple-faults)
        // helpful to debug core-booting related failures:
        .qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_string("Hello from the other side")?.as_str();
        output += p.exp_string("Core has started")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test TLS is working on the BSP and other cores
#[test]
fn s02_tls() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("thread-local", &build).cores(2);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can multiple cores and use the node-replication log to communicate.
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s02_nvdimm_discover() {
    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("nvdimm-discover", &build)
        .nodes(2)
        .cores(2)
        .pmem(1024);

    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");

        output += p.exp_string("NVDIMMs Discovered")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can use GDB for kernel debugging.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s02_gdb() {
    /// Spawn the gdb debugger
    pub fn spawn_gdb(binary: &str) -> Result<PtyReplSession> {
        // The `-nx` ignores any potential .gdbinit files that may mess with the test
        spawn(format!("gdb -nx {}", binary).as_str(), Some(3_000)).map(|p| PtyReplSession {
            prompt: "(gdb) ".to_string(),
            pty_session: p,
            quit_command: Some("quit".to_string()),
            echo_on: false,
        })
    }

    let build = BuildArgs::default().kernel_feature("gdb").build();
    let cmdline = RunnerArgs::new_with_build("gdb", &build).kgdb().cores(1);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");
        // Wait until kernel is waiting for debugger:
        output += p
            .exp_string("Use `target remote localhost:1234` in gdb to connect.")?
            .as_str();

        // Spawn GDB
        let binary = if cmdline.build_args.release {
            "../target/x86_64-uefi/release/esp/kernel"
        } else {
            "../target/x86_64-uefi/debug/esp/kernel"
        };
        let mut gdb = spawn_gdb(binary)?;
        output += gdb.wait_for_prompt()?.as_str();

        // Perform some basic functionality test which exercises the gdb code:

        // Test connection
        gdb.send_line("target remote localhost:1234")?;
        output += p.exp_string("Debugger connected.")?.as_str();
        output += gdb
            .exp_string("Remote debugging using localhost:1234")?
            .as_str();

        // Test symbol resolution (`SectionOffsets`) and reads from memory
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("print cmdline")?;
        output += gdb
            .exp_string("nrk::cmdline::CommandLineArguments")?
            .as_str();

        // Test hardware breakpoints: `hbreak`, `continue`
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("hbreak gdb")?;
        output += gdb.exp_string("Hardware assisted breakpoint 1")?.as_str();

        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("continue")?;
        output += gdb.exp_string("Breakpoint 1")?.as_str();

        // Test watchpoints
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("step")?; // Need one step so `watchpoint_trigger` is "in context"

        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("watch -l watchpoint_trigger")?;
        output += gdb.exp_string("Hardware watchpoint 2")?.as_str();

        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("continue")?;

        output += gdb
            .exp_string("Hardware watchpoint 2: -location watchpoint_trigger")?
            .as_str();
        output += gdb.exp_string("Old value = 0")?.as_str();
        output += gdb.exp_string("New value = 3735928559")?.as_str();

        for _i in 0..15 {
            // Test if we can step through info!("") -- lots of steps  just do 15
            output += gdb.wait_for_prompt()?.as_str();
            gdb.send_line("step")?;
        }

        // Test `continue`
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("continue")?;
        output += gdb.exp_string("Remote connection closed")?.as_str();

        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests that basic file-system support is functional.
///
/// This tests various file-system systemcalls such as:
///  * File open, close
///  * File read, write
///  * File getinfo
///  * All the above operations with invalid userspace pointers
#[test]
fn s02_test_fs() {
    let build = BuildArgs::default()
        .module("init")
        .user_feature("test-fs")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace-smp", &build).timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        p.exp_string("fs_test OK")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Property tests for file-system support.
///
/// This tests various file-system systemcalls such as:
///  * File open, close
///  * File read, write
///  * File getinfo
#[test]
fn s02_test_fs_prop() {
    let build = BuildArgs::default()
        .module("init")
        .user_feature("test-fs-prop")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build).timeout(120_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        p.exp_string("fs_prop_test OK")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Checks vspace debug functionality.
#[test]
fn s02_vspace_debug() {
    /// Checks output for graphviz content, and creates PNGs from it
    fn plot_vspace(output: &String) -> io::Result<()> {
        let mut file = File::create("vspace.dot")?;
        file.write_all(output.as_bytes())?;
        eprintln!("About to invoke dot...");

        let o = process::Command::new("sfdp")
            .args(["-Tsvg", "vspace.dot", "-O"])
            .output()
            .expect("failed to create graph");
        if !o.status.success() {
            io::stdout().write_all(&o.stdout).unwrap();
            io::stderr().write_all(&o.stderr).unwrap();
            panic!("Graphviz invocation failed");
        }

        Ok(())
    }

    let build = BuildArgs::default().build();
    let cmdline = &RunnerArgs::new_with_build("vspace-debug", &build)
        .timeout(45_000)
        .memory(2048);
    let mut output = String::new();
    let mut graphviz_output = String::new();

    const GRAPHVIZ_START: &str = "===== graphviz =====";
    const GRAPHVIZ_END: &str = "===== end graphviz =====";

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(cmdline)?;
        output += p.exp_string(GRAPHVIZ_START)?.as_str();
        graphviz_output = p.exp_string(GRAPHVIZ_END)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(cmdline, qemu_run(), output);
    plot_vspace(&graphviz_output).expect("Can't plot vspace");
}
