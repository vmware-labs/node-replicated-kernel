//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s00_*`: Core kernel functionality like boot-up and fault handling
//! * `s01_*`: Low level kernel services: SSE, memory allocation etc.
//! * `s02_*`: High level kernel services: ACPI, core booting mechanism, NR, VSpace etc.
//! * `s03_*`: High level kernel functionality: Spawn cores, run user-space programs
//! * `s04_*`: User-space runtimes
//! * `s05_*`: User-space applications
//! * `s06_*`: User-space applications benchmarks
#![feature(vec_remove_item)]

extern crate rexpect;
#[macro_use]
extern crate matches;

use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::process;

use csv::WriterBuilder;
use rexpect::errors::*;
use rexpect::process::{signal::SIGTERM, wait::WaitStatus};
use rexpect::session::spawn_command;
use rexpect::{spawn, spawn_bash};
use serde::Serialize;

const REDIS_PORT: u16 = 6379;

/// Different ExitStatus codes as returned by Bespin.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
enum ExitStatus {
    /// Successful exit.
    Success,
    /// ReturnFromMain: main() function returned to arch_indepdendent part.
    ReturnFromMain,
    /// Encountered kernel panic.
    KernelPanic,
    /// Encountered OOM.
    OutOfMemory,
    /// Encountered an interrupt that led to an exit.
    UnexpectedInterrupt,
    /// General Protection Fault.
    GeneralProtectionFault,
    /// Unexpected Page Fault.
    PageFault,
    /// Unexpected process exit code when running a user-space test.
    UnexpectedUserSpaceExit,
    /// Exception happened during kernel initialization.
    ExceptionDuringInitialization,
    /// An unrecoverable error happened (double-fault etc).
    UnrecoverableError,
    /// Kernel exited with unknown error status... Update the script.
    Unknown(i8),
}

impl From<i8> for ExitStatus {
    fn from(exit_code: i8) -> Self {
        match exit_code {
            0 => ExitStatus::Success,
            1 => ExitStatus::ReturnFromMain,
            2 => ExitStatus::KernelPanic,
            3 => ExitStatus::OutOfMemory,
            4 => ExitStatus::UnexpectedInterrupt,
            5 => ExitStatus::GeneralProtectionFault,
            6 => ExitStatus::PageFault,
            7 => ExitStatus::UnexpectedUserSpaceExit,
            8 => ExitStatus::ExceptionDuringInitialization,
            9 => ExitStatus::UnrecoverableError,
            _ => ExitStatus::Unknown(exit_code),
        }
    }
}

impl Display for ExitStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let desc = match self {
            ExitStatus::Success => "Success!",
            ExitStatus::ReturnFromMain => {
                "ReturnFromMain: main() function returned to arch_indepdendent part"
            }
            ExitStatus::KernelPanic => "KernelPanic: Encountered kernel panic",
            ExitStatus::OutOfMemory => "OutOfMemory: Encountered OOM",
            ExitStatus::UnexpectedInterrupt => "Encountered unexpected Interrupt",
            ExitStatus::GeneralProtectionFault => {
                "Encountered unexpected General Protection Fault: "
            }
            ExitStatus::PageFault => "Encountered unexpected Page Fault",
            ExitStatus::UnexpectedUserSpaceExit => {
                "Unexpected process exit code when running a user-space test"
            }
            ExitStatus::ExceptionDuringInitialization => {
                "Got an interrupt/exception during kernel initialization"
            }
            ExitStatus::UnrecoverableError => "An unrecoverable error happened (double-fault etc).",
            ExitStatus::Unknown(_) => {
                "Unknown: Kernel exited with unknown error status... Update the code!"
            }
        };

        write!(f, "{}", desc)
    }
}

/// Arguments passed to the run.py script to configure a test.
#[derive(Clone)]
struct RunnerArgs<'a> {
    /// Test name of kernel integration test.
    kernel_features: Vec<&'a str>,
    /// Features passed to compiled user-space modules.
    user_features: Vec<&'a str>,
    /// Number of NUMA nodes the VM should have.
    nodes: usize,
    /// Number of cores the VM should have.
    cores: usize,
    /// Total memory of the system (in MiB).
    memory: usize,
    /// Kernel command line argument.
    cmd: Option<&'a str>,
    /// Which user-space modules to include.
    mods: Vec<&'a str>,
    /// Should we compile in release mode?
    release: bool,
    /// If true don't run, just compile.
    norun: bool,
    /// Parameters to add to the QEMU command line
    qemu_args: Vec<&'a str>,
    /// Timeout in ms
    timeout: u64,
    /// Default network interface for QEMU
    nic: &'static str,
    /// Pin QEMU cpu threads
    setaffinity: bool,
}

#[allow(unused)]
impl<'a> RunnerArgs<'a> {
    fn new(kernel_test: &'a str) -> RunnerArgs {
        RunnerArgs {
            kernel_features: vec![kernel_test],
            user_features: Vec::new(),
            nodes: 0,
            cores: 1,
            memory: 1024,
            cmd: None,
            mods: Vec::new(),
            release: false,
            norun: false,
            qemu_args: Vec::new(),
            timeout: 15_000,
            nic: "e1000",
            setaffinity: false,
        }
    }

    /// What cargo features should be passed to the kernel build.
    fn kernel_features(mut self, kernel_features: &[&'a str]) -> RunnerArgs<'a> {
        self.kernel_features.extend_from_slice(kernel_features);
        self
    }

    /// Add a cargo feature to the kernel build.
    fn kernel_feature(mut self, kernel_feature: &'a str) -> RunnerArgs<'a> {
        self.kernel_features.push(kernel_feature);
        self
    }

    /// What cargo features should be passed to the user-space modules build.
    fn user_features(mut self, user_features: &[&'a str]) -> RunnerArgs<'a> {
        self.user_features.extend_from_slice(user_features);
        self
    }

    /// Add a cargo feature to the user-space modules build.
    fn user_feature(mut self, user_feature: &'a str) -> RunnerArgs<'a> {
        self.user_features.push(user_feature);
        self
    }

    /// How many NUMA nodes QEMU should simulate.
    fn nodes(mut self, nodes: usize) -> RunnerArgs<'a> {
        self.nodes = nodes;
        self
    }

    /// How many NUMA nodes QEMU should simulate.
    fn use_virtio(mut self) -> RunnerArgs<'a> {
        self.nic = "virtio";
        self
    }

    /// How many cores QEMU should simulate.
    fn cores(mut self, cores: usize) -> RunnerArgs<'a> {
        self.cores = cores;
        self
    }

    /// How much total system memory (in MiB) that the instance should get.
    ///
    /// The amount is evenly divided among all nodes.
    fn memory(mut self, mibs: usize) -> RunnerArgs<'a> {
        self.memory = mibs;
        self
    }

    /// Command line passed to the kernel.
    fn cmd(mut self, cmd: &'a str) -> RunnerArgs<'a> {
        self.cmd = Some(cmd);
        self
    }

    /// Which user-space modules we want to include.
    fn modules(mut self, mods: &[&'a str]) -> RunnerArgs<'a> {
        self.mods.extend_from_slice(mods);
        self
    }

    /// Adds a user-space module to the build and deployment.
    fn module(mut self, module: &'a str) -> RunnerArgs<'a> {
        self.mods.push(module);
        self
    }

    /// Do a release build.
    fn release(mut self) -> RunnerArgs<'a> {
        self.release = true;
        self
    }

    /// Don't run, just build.
    fn norun(mut self) -> RunnerArgs<'a> {
        self.norun = true;
        self
    }

    /// Which arguments we want to add to QEMU.
    fn qemu_args(mut self, args: &[&'a str]) -> RunnerArgs<'a> {
        self.qemu_args.extend_from_slice(args);
        self
    }

    /// Adds an argument to QEMU.
    fn qemu_arg(mut self, arg: &'a str) -> RunnerArgs<'a> {
        self.qemu_args.push(arg);
        self
    }

    fn timeout(mut self, timeout: u64) -> RunnerArgs<'a> {
        self.timeout = timeout;
        self
    }

    fn setaffinity(mut self) -> RunnerArgs<'a> {
        self.setaffinity = true;
        self
    }

    /// Converts the RunnerArgs to a run.py command line invocation.
    fn as_cmd(&'a self) -> Vec<String> {
        use std::ops::Add;
        // Add features for build
        let kernel_features = String::from(self.kernel_features.join(","));
        let user_features = String::from(self.user_features.join(","));

        let log_level = match std::env::var("RUST_LOG") {
            Ok(lvl) if lvl == "debug" => "debug",
            Ok(lvl) if lvl == "trace" => "trace",
            Ok(lvl) if lvl == "warn" => "warn",
            Ok(lvl) if lvl == "error" => "error",
            Ok(lvl) if lvl == "info" => "info",
            _ => "info",
        };

        let mut cmd = vec![
            String::from("run.py"),
            String::from("--kfeatures"),
            kernel_features,
            String::from("--cmd"),
            format!("log={} {}", log_level, self.cmd.unwrap_or("")),
            String::from("--nic"),
            String::from(self.nic),
        ];

        if !self.mods.is_empty() {
            cmd.push("--mods".to_string());
            cmd.push(self.mods.join(" "));
        }

        match self.user_features.is_empty() {
            false => {
                cmd.push(String::from("--ufeatures"));
                cmd.push(user_features);
            }
            true => {}
        };

        if self.release {
            cmd.push(String::from("--release"));
        }

        cmd.push(String::from("--qemu-cores"));
        cmd.push(format!("{}", self.cores));

        cmd.push(String::from("--qemu-nodes"));
        cmd.push(format!("{}", self.nodes));

        cmd.push(String::from("--qemu-memory"));
        cmd.push(format!("{}", self.memory));

        if self.setaffinity {
            cmd.push(String::from("--qemu-affinity"));
        }

        // Form arguments for QEMU
        let mut qemu_args: Vec<String> = self.qemu_args.iter().map(|arg| arg.to_string()).collect();
        if !qemu_args.is_empty() {
            cmd.push(format!("--qemu-settings={}", qemu_args.join(" ")));
        }

        // Don't run qemu, just build?
        match self.norun {
            false => {}
            true => {
                cmd.push(String::from("--norun"));
            }
        };

        cmd
    }
}

fn check_for_successful_exit(args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
    check_for_exit(ExitStatus::Success, args, r, output);
}

fn check_for_exit(expected: ExitStatus, args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
    fn log_qemu_out(args: &RunnerArgs, output: String) {
        if !output.is_empty() {
            println!("\n===== QEMU LOG =====");
            println!("{}", &output);
            println!("===== END QEMU LOG =====");
        }

        let quoted_cmd = args
            .as_cmd()
            .into_iter()
            .map(|mut arg| {
                arg.insert(0, '"');
                arg.push('"');
                arg
            })
            .collect::<Vec<String>>()
            .join(" ");

        println!("We invoked: python3 {}", quoted_cmd);
    }

    match r {
        Ok(WaitStatus::Exited(_, code)) => {
            let exit_status: ExitStatus = code.into();
            if exit_status != expected {
                log_qemu_out(args, output);
                if expected != ExitStatus::Success {
                    println!("We expected to exit with {}, but", expected);
                }
                panic!("Unexpected exit code from QEMU: {}", exit_status);
            }
            // else: We're good
        }
        Err(e) => {
            log_qemu_out(args, output);
            panic!("Qemu testing failed: {}", e);
        }
        e => {
            log_qemu_out(args, output);
            panic!(
                "Something weird happened to the Qemu process, please investigate: {:?}",
                e
            );
        }
    };
}

/// Builds the kernel and spawns a qemu instance of it.
///
/// For kernel-code it gets compiled with kernel features `integration-test`
/// and whatever feature is supplied in `test`. For user-space modules
/// we pass everything in `user_features` to the build.
///
/// It will make sure the code is compiled and ready to launch.
/// Otherwise the 15s timeout we set on the PtySession may not be enough
/// to build from scratch and run the test.
fn spawn_bespin(args: &RunnerArgs) -> Result<rexpect::session::PtySession> {
    // Compile the code with correct settings first:
    let cloned_args = args.clone();
    let compile_args = cloned_args.norun();

    let o = process::Command::new("python3")
        .args(compile_args.as_cmd())
        .output()
        .expect("failed to build");
    if !o.status.success() {
        io::stdout().write_all(&o.stdout).unwrap();
        io::stderr().write_all(&o.stderr).unwrap();
        panic!(
            "Building test failed: {:?}",
            compile_args.as_cmd().join(" ")
        );
    }

    let mut o = process::Command::new("python3");
    o.args(args.as_cmd());

    eprintln!("Invoke QEMU: {:?}", o);
    spawn_command(o, Some(args.timeout))
}

/// Spawns a DHCP server on our host
///
/// It uses our dhcpd config and listens on the tap0 interface
/// (that we set up in our run.py script).
fn spawn_dhcpd() -> Result<rexpect::session::PtyBashSession> {
    // apparmor prevents reading of ./tests/dhcpd.conf for dhcpd
    // on Ubuntu, so we make sure it is disabled:
    let _o = process::Command::new("sudo")
        .args(&["service", "apparmor", "stop"])
        .output()
        .expect("failed to disable apparmor");
    let _o = process::Command::new("sudo")
        .args(&["killall", "dhcpd"])
        .output()
        .expect("failed to shut down dhcpd");

    // Spawn a bash session for dhcpd, otherwise it seems we
    // can't kill the process since we do not run as root
    let mut b = spawn_bash(Some(20000))?;
    b.send_line("sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf")?;
    Ok(b)
}

/// Helper function that spawns a UDP receiver socket on the host.
fn spawn_receiver() -> Result<rexpect::session::PtySession> {
    spawn("socat UDP-LISTEN:8889,fork stdout", Some(20000))
}

/// Helper function that tries to ping the QEMU guest.
fn spawn_ping() -> Result<rexpect::session::PtySession> {
    spawn("ping 172.31.0.10", Some(20000))
}

fn spawn_nc(port: u16) -> Result<rexpect::session::PtySession> {
    spawn(format!("nc 172.31.0.10 {}", port).as_str(), Some(20000))
}

/// Make sure exiting the kernel works.
///
/// We have a special ioport that we use to signal the exit to
/// qemu and some parsing logic to read the exit code
/// and communicate if our tests passed or failed.
#[test]
fn s00_exit() {
    let cmdline = RunnerArgs::new("test-exit");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
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
    let cmdline = RunnerArgs::new("test-pfault-early").qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
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

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn s01_pfault() {
    let cmdline = RunnerArgs::new("test-pfault");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("[IRQ] Page Fault")?;
        p.exp_regex("Backtrace:")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_exit(ExitStatus::PageFault, &cmdline, qemu_run(), output);
}

/// Make sure the general-protection-fault handler works as expected  -- even if
/// we're early on in initialization.
/// In essence a trap should be raised but we can't get a backtrace yet
/// since we don't have memory allocation.
#[test]
fn s00_gpfault_early() {
    let cmdline = RunnerArgs::new("test-gpfault-early").qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
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

/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
#[test]
fn s01_gpfault() {
    let cmdline = RunnerArgs::new("test-gpfault");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #3  - 0x[0-9a-fA-F]+ - bespin::xmain")?;
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
    let cmdline = RunnerArgs::new("test-double-fault").qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
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
    let cmdline = RunnerArgs::new("test-alloc");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
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
    let cmdline = RunnerArgs::new("test-sse");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("division = 4.566210045662101")?;
        p.exp_string("division by zero = inf")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

#[test]
fn s01_time() {
    let cmdline = RunnerArgs::new("test-time").release();
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

#[test]
fn s01_timer() {
    let cmdline = RunnerArgs::new("test-timer");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        output += p.exp_string("Setting the timer")?.as_str();
        output += p.exp_string("Got a timer interrupt")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology.
#[test]
fn s02_acpi_topology() {
    let cmdline = &RunnerArgs::new("test-acpi-topology")
        .cores(80)
        .nodes(8)
        .memory(4096);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline).expect("Can't spawn QEMU instance");

        p.exp_string("ACPI Initialized")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology
/// (a different one than acpi_smoke).
#[test]
fn s02_acpi_smoke() {
    let cmdline = &RunnerArgs::new("test-acpi-smoke").cores(2).memory(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline).expect("Can't spawn QEMU instance");

        p.exp_string("ACPI Initialized")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can boot an additional core.
///
/// Utilizes the app core initializtion logic
/// as well as the APIC driver (sending IPIs).
#[test]
fn s02_coreboot_smoke() {
    let cmdline = RunnerArgs::new("test-coreboot-smoke")
        .cores(2)
        // Adding this to qemu will print register state on CPU rests (triple-faults)
        // helpful to debug core-booting related failures:
        .qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("ACPI Initialized")?;
        p.exp_string("Hello from the other side")?;
        p.exp_string("Core has started")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can multiple cores and use the node-replication log to communicate.
#[test]
fn s02_coreboot_nrlog() {
    let cmdline = RunnerArgs::new("test-coreboot-nrlog")
        .cores(4)
        // Adding this to qemu will print register state on CPU rests (triple-faults)
        // helpful to debug core-booting related failures:
        .qemu_arg("-d int,cpu_reset");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("ACPI Initialized")?;
        p.exp_string("Hello from the other side")?;
        p.exp_string("Core has started")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we boot up all cores in the system.
#[test]
fn s03_coreboot() {
    let cmdline = &RunnerArgs::new("test-coreboot")
        .cores(32)
        .nodes(4)
        .memory(4096);
    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline).expect("Can't spawn QEMU instance");

        for i in 1..32 {
            // Check that we see all 32 cores booting up
            let expected_output = format!("Core #{} initialized", i);
            p.exp_string(expected_output.as_str())?;
        }

        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests that basic user-space support is functional.
///
/// This tests various user-space components such as:
///  * process loading
///  * system calls (printing, mem. mgmt.)
///  * user-space scheduling and upcalls
///  * BSD libOS in user-space
#[test]
fn s03_userspace_smoke() {
    let cmdline = RunnerArgs::new("test-userspace").user_features(&[
        "test-print",
        "test-map",
        "test-alloc",
        "test-upcall",
        "test-scheduler",
    ]);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;

        p.exp_string("print_test OK")?;
        p.exp_string("upcall_test OK")?;
        p.exp_string("map_test OK")?;
        p.exp_string("alloc_test OK")?;
        p.exp_string("scheduler_test OK")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests the lineup scheduler multi-core ability.
///
/// Makes sure we can request cores and spawn threads on said cores.
#[test]
fn s04_userspace_multicore() {
    const NUM_CORES: usize = 56;
    let cmdline = RunnerArgs::new("test-userspace-smp")
        .user_features(&["test-scheduler-smp"])
        .cores(NUM_CORES)
        .memory(2048)
        .timeout(28_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;

        for _i in 0..NUM_CORES {
            let r = p.exp_regex(r#"init: Hello from core (\d+)"#)?;
            output += r.0.as_str();
            output += r.1.as_str();
        }

        p.process.kill(SIGTERM)
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

/// Tests that user-space networking is functional.
///
/// This tests various user-space components such as:
///  * BSD libOS network stack
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
#[test]
fn s04_userspace_rumprt_net() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_bespin(
            &RunnerArgs::new("test-userspace")
                .user_feature("test-rump-net")
                .timeout(20_000),
        )?;

        // Test that DHCP works:
        dhcp_server.exp_string("DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0")?;

        // Test that sendto works:
        // Used to swallow just the first packet (see also: https://github.com/rumpkernel/rumprun/issues/131)
        // Update: Now on NetBSD v8 it swallows the first 6-8 packets
        receiver.exp_string("pkt 10")?;
        receiver.exp_string("pkt 11")?;
        receiver.exp_string("pkt 12")?;

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

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

/// Tests the rump FS.
///
/// Checks that we can initialize a BSD libOS and run FS operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
#[test]
fn s04_userspace_rumprt_fs() {
    let cmdline = &RunnerArgs::new("test-userspace")
        .user_feature("test-rump-tmpfs")
        .timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("bytes_written: 12")?;
        p.exp_string("bytes_read: 12")?;
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
            .args(&["-Tsvg", "vspace.dot", "-O"])
            .output()
            .expect("failed to create graph");
        if !o.status.success() {
            io::stdout().write_all(&o.stdout).unwrap();
            io::stderr().write_all(&o.stderr).unwrap();
            panic!("Graphviz invocation failed: {:?}");
        }

        Ok(())
    }

    let cmdline = &RunnerArgs::new("test-vspace-debug")
        .timeout(45_000)
        .memory(2048);
    let mut output = String::new();
    let mut graphviz_output = String::new();

    const GRAPHVIZ_START: &'static str = "===== graphviz =====";
    const GRAPHVIZ_END: &'static str = "===== end graphviz =====";

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        output += p.exp_string(GRAPHVIZ_START)?.as_str();
        graphviz_output = p.exp_string(GRAPHVIZ_END)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
    plot_vspace(&graphviz_output).expect("Can't plot vspace");
}

fn _multi_process() {
    let cmdline = &RunnerArgs::new("test-userspace-multi").user_feature("test-loopy");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        output += p.exp_string("Process 1 looping")?.as_str();
        output += p.exp_string("Process 2 looping")?.as_str();
        output += p.exp_string("Process 1 looping")?.as_str();
        output += p.exp_string("Process 2 looping")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests that user-space application redis is functional
/// by spawing it and connecting to it from the network.
///
/// This tests various user-space components such as:
///  * Build and linking of user-space libraries
///  * BSD libOS network stack, libc and pthreads
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
///  * (kernel memfs eventually for DB persistence)
#[test]
fn s05_redis_smoke() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;

        let mut p = spawn_bespin(
            &RunnerArgs::new("test-userspace")
                .module("rkapps")
                .user_feature("rkapps:redis")
                .cmd("testbinary=redis.bin")
                .timeout(20_000),
        )?;

        // Test that DHCP works:
        dhcp_server.exp_string("DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0")?;
        p.exp_string("# Server started, Redis version 3.0.6")?;

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

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

fn redis_benchmark(nic: &'static str, requests: usize) -> Result<rexpect::session::PtySession> {
    fn spawn_bencher(port: u16, requests: usize) -> Result<rexpect::session::PtySession> {
        spawn(
            format!(
                "redis-benchmark -h 172.31.0.10 -p {} -t ping,get,set -n {} -P 30 --csv",
                port, requests
            )
            .as_str(),
            Some(25000),
        )
    }

    let mut redis_client = spawn_bencher(REDIS_PORT, requests)?;
    // redis reports the tputs as floating points
    redis_client.exp_string("\"PING_INLINE\",\"")?;
    let (_line, ping_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"PING_BULK\",\"")?;
    let (_line, ping_bulk_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"SET\",\"")?;
    let (_line, set_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"GET\",\"")?;
    let (_line, get_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    let ping_tput: f64 = ping_tput.parse().unwrap_or(404.0);
    let ping_bulk_tput: f64 = ping_bulk_tput.parse().unwrap_or(404.0);
    let set_tput: f64 = set_tput.parse().unwrap_or(404.0);
    let get_tput: f64 = get_tput.parse().unwrap_or(404.0);

    // Append parsed results to a CSV file
    let file_name = "redis_benchmark.csv";
    // write headers only to a new file
    let write_headers = !Path::new(file_name).exists();
    let csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let mut wtr = WriterBuilder::new()
        .has_headers(write_headers)
        .from_writer(csv_file);

    #[derive(Serialize)]
    struct Record {
        git_rev: &'static str,
        ping: f64,
        ping_bulk: f64,
        set: f64,
        get: f64,
    };

    let record = Record {
        git_rev: env!("GIT_HASH"),
        ping: ping_tput,
        ping_bulk: ping_bulk_tput,
        set: set_tput,
        get: get_tput,
    };

    wtr.serialize(record).expect("Can't write results");

    println!("git_rev,nic,ping,ping_bulk,set,get");
    println!(
        "{},{},{},{},{},{}",
        env!("GIT_HASH"),
        nic,
        ping_tput,
        ping_bulk_tput,
        set_tput,
        get_tput
    );
    assert!(
        get_tput > 200_000.0,
        "Redis throughput seems rather low (GET < 200k)?"
    );

    Ok(redis_client)
}

#[test]
fn s06_redis_benchmark_virtio() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;

        let mut p = spawn_bespin(
            &RunnerArgs::new("test-userspace")
                .module("rkapps")
                .user_feature("rkapps:redis")
                .cmd("testbinary=redis.bin")
                .use_virtio()
                .release()
                .timeout(30_000),
        )?;

        // Test that DHCP works:
        dhcp_server.exp_string("DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0")?;
        p.exp_string("# Server started, Redis version 3.0.6")?;

        use std::{thread, time};
        thread::sleep(time::Duration::from_secs(4));

        let mut redis_client = redis_benchmark("virtio", 4000000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

#[test]
fn s06_redis_benchmark_e1000() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;

        let mut p = spawn_bespin(
            &RunnerArgs::new("test-userspace")
                .module("rkapps")
                .user_feature("rkapps:redis")
                .cmd("testbinary=redis.bin")
                .release()
                .timeout(30_000),
        )?;

        // Test that DHCP works:
        dhcp_server.exp_string("DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0")?;
        p.exp_string("# Server started, Redis version 3.0.6")?;
        p.exp_string("* The server is now ready to accept connections on port 6379")?;

        use std::{thread, time};
        thread::sleep(time::Duration::from_secs(6));

        let mut redis_client = redis_benchmark("e1000", 3000000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

pub fn thread_defaults(max_cores: usize) -> Vec<usize> {
    let mut threads = Vec::with_capacity(12);

    // On larger machines thread increments are bigger than on
    // smaller machines:
    let thread_incremements = if max_cores > 120 {
        16
    } else if max_cores > 24 {
        8
    } else if max_cores > 16 {
        4
    } else {
        2
    };

    for t in (0..(max_cores + 1)).step_by(thread_incremements) {
        if t == 0 {
            // Can't run on 0 threads
            threads.push(t + 1);
        } else {
            threads.push(t);
        }
    }

    threads.sort();
    threads
}

#[test]
fn s06_vmops_benchmark() {
    let max_cores = if num_cpus::get() > 12 && num_cpus::get() % 2 == 0 {
        num_cpus::get() / 2
    } else {
        num_cpus::get()
    };

    let threads = if cfg!(feature = "smoke") {
        vec![1, 4]
    } else {
        thread_defaults(max_cores)
    };

    let file_name = "vmops_benchmark.csv";
    std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("testcmd={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("bench-vmops")
            .timeout(12_000 + cores as u64 * 3000)
            .cores(max_cores)
            .setaffinity()
            .release()
            .cmd(kernel_cmdline.as_str());
        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(8192);
        } else {
            cmdline = cmdline.memory(56 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            let max_cores = num_cpus::get();
            // TODO(ergnomics): Hard-coded skylake2x and skylake4x topology:
            match max_cores {
                28 => cmdline = cmdline.nodes(2),
                56 => cmdline = cmdline.nodes(2),
                96 => cmdline = cmdline.nodes(4),
                192 => cmdline = cmdline.nodes(4),
                _ => {}
            };
        }

        let mut output = String::new();
        let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_bespin(&cmdline)?;

            // Parse lines like
            // `init::vmops: 1,maponly,1,4096,10000,1000,634948`
            // write them to a CSV file
            let expected_lines = if cfg!(feature = "smoke") {
                1
            } else {
                with_cores * 11
            };

            for _i in 0..expected_lines {
                let (prev, matched) =
                    p.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
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
                        "git_rev,thread_id,benchmark,ncores,memsize,duration_total,duration,operations\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let parts: Vec<&str> = matched.split("init::vmops: ").collect();
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

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s06_vmops_latency_benchmark() {
    let max_cores = if num_cpus::get() > 12 && num_cpus::get() % 2 == 0 {
        num_cpus::get() / 2
    } else {
        num_cpus::get()
    };

    let threads = if cfg!(feature = "smoke") {
        vec![1, 4]
    } else {
        thread_defaults(max_cores)
    };

    let file_name = "vmops_benchmark_latency.csv";
    std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("testcmd={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("bench-vmops")
            .user_feature("latency")
            .timeout(25_000 + cores as u64 * 100_000)
            .cores(max_cores)
            .setaffinity()
            .release()
            .cmd(kernel_cmdline.as_str());
        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(8192);
        } else {
            cmdline = cmdline.memory(56 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            let max_cores = num_cpus::get();
            // TODO(ergnomics): Hard-coded skylake2x and skylake4x topology:
            match max_cores {
                28 => cmdline = cmdline.nodes(2),
                56 => cmdline = cmdline.nodes(2),
                96 => cmdline = cmdline.nodes(4),
                192 => cmdline = cmdline.nodes(4),
                _ => {}
            };
        }

        let mut output = String::new();
        let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_bespin(&cmdline)?;

            // Parse lines like
            // `init::vmops: 1,maponly,1,4096,10000,1000,634948`
            // write them to a CSV file
            let expected_lines = if cfg!(feature = "smoke") {
                1
            } else {
                with_cores * 1_000
            };

            for _i in 0..expected_lines {
                let (prev, matched) =
                    p.exp_regex(r#"init::vmops: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
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
                        "git_rev,thread_id,benchmark,ncores,memsize,samples_total,sample_id,latency\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let parts: Vec<&str> = matched.split("init::vmops: ").collect();
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

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s06_memfs_bench() {
    let max_cores = if num_cpus::get() > 12 && num_cpus::get() % 2 == 0 {
        num_cpus::get() / 2
    } else {
        num_cpus::get()
    };

    let threads = if cfg!(feature = "smoke") {
        vec![1, 4]
    } else {
        thread_defaults(max_cores)
    };

    let file_name = "memfs_benchmark.csv";
    std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("testcmd={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("fs-bench")
            .memory(1024)
            .timeout(25_000 + cores as u64 * 1000)
            .cores(max_cores)
            .setaffinity()
            .cmd(kernel_cmdline.as_str())
            .release();

        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(8192);
        } else {
            cmdline = cmdline.memory(core::cmp::max(8192, cores * 512));
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            let max_cores = num_cpus::get();
            // TODO(ergnomics): Hard-coded skylake2x and skylake4x topology:
            match max_cores {
                28 => cmdline = cmdline.nodes(2),
                56 => cmdline = cmdline.nodes(2),
                96 => cmdline = cmdline.nodes(4),
                192 => cmdline = cmdline.nodes(4),
                _ => {}
            };
        }

        let mut output = String::new();
        let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_bespin(&cmdline)?;

            // Parse lines like
            // `init::fsbench: 1,readonly,2,2048,10000,4000,1863272`
            // write them to a CSV file
            let expected_lines = if cfg!(feature = "smoke") {
                1
            } else {
                with_cores * 11
            };

            for _i in 0..expected_lines {
                let (prev, matched) =
                    p.exp_regex(r#"init::fsbench: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
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
                        "git_rev,thread_id,benchmark,ncores,memsize,duration_total,duration,operations\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let parts: Vec<&str> = matched.split("init::fsbench: ").collect();
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
        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}
