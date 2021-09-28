// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::{io, process};

use hwloc2::{ObjectType, Topology};

use csv::WriterBuilder;
use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::session::{spawn_command, PtyReplSession};
use rexpect::{spawn, spawn_bash};
use serde::Serialize;

/// Port we use for the Redis instances.
const REDIS_PORT: u16 = 6379;

/// Line we use to tell if Redis has started.
const REDIS_START_MATCH: &'static str = "# Server initialized";

/// Line we use in dhcpd to match for giving IP to qemu VM.
const DHCP_ACK_MATCH: &'static str = "DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0";

/// Environment variable that points to machine config (for baremetal booting)
const BAREMETAL_MACHINE: &'static str = "BAREMETAL_MACHINE";

/// Different ExitStatus codes as returned by NRK.
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
    Unknown(i32),
}

impl From<i32> for ExitStatus {
    fn from(exit_code: i32) -> Self {
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

/// Different machine types we can run on.
#[derive(Eq, PartialEq, Debug, Clone)]
enum Machine {
    /// A bare-metal machine identified by a string.
    /// The name is described in the corresponding TOML file.
    ///
    /// (e.g., Machine::BareMetal("b1542".into()) should have a corresponding b1542.toml file).
    Baremetal(String),
    /// Run on a virtual machine with QEMU (machine parameters determined by current host)
    Qemu,
}

impl Machine {
    fn determine() -> Self {
        match std::env::var(BAREMETAL_MACHINE) {
            Ok(name) => {
                if name.is_empty() {
                    panic!("{} enviroment variable empty.", BAREMETAL_MACHINE);
                }
                if !Path::new(&name).exists() {
                    panic!(
                        "'{}.toml' file not found. Check {} enviroment variable.",
                        name, BAREMETAL_MACHINE
                    );
                }
                Machine::Baremetal(name)
            }
            _ => Machine::Qemu,
        }
    }

    fn name(&self) -> &str {
        match self {
            Machine::Qemu => "qemu",
            Machine::Baremetal(s) => s.as_str(),
        }
    }

    /// Return a set of cores to run benchmark, run fewer total iterations
    /// and instead more with high core counts.
    fn thread_defaults_low_mid_high(&self) -> Vec<usize> {
        if cfg!(feature = "smoke") {
            return vec![1, 4];
        }

        let uniform_threads = self.thread_defaults_uniform();
        let mut threads = Vec::with_capacity(6);

        for low in uniform_threads.iter().take(2) {
            threads.push(*low);
        }

        let mid = uniform_threads.len() / 2;
        if let Some(e) = uniform_threads.get(mid) {
            threads.push(*e);
        }

        for high in uniform_threads.iter().rev().take(3) {
            threads.push(*high);
        }

        threads.sort_unstable();
        threads.dedup();

        threads
    }

    /// Return a set of cores to run benchmark on sampled uniform between
    /// 1..self.max_cores().
    fn thread_defaults_uniform(&self) -> Vec<usize> {
        if cfg!(feature = "smoke") {
            return vec![1, 4];
        }

        let max_cores = self.max_cores();
        let nodes = self.max_numa_nodes();

        let mut threads = Vec::with_capacity(12);
        // On larger machines thread increments are bigger than on smaller
        // machines:
        let thread_incremements = if max_cores > 96 {
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

        threads.push(max_cores / nodes);
        threads.push(max_cores);

        threads.sort_unstable();
        threads.dedup();

        threads
    }

    fn max_cores(&self) -> usize {
        if let Machine::Qemu = self {
            let topo = Topology::new().expect("Can't retrieve System topology?");
            topo.objects_with_type(&ObjectType::Core)
                .map_or(1, |cpus| cpus.len())
        } else {
            match self.name() {
                "l0318" => 96,
                "b1542" => 28,
                _ => unreachable!("unknown machine"),
            }
        }
    }

    fn max_numa_nodes(&self) -> usize {
        if let Machine::Qemu = self {
            let topo = Topology::new().expect("Can't retrieve System topology?");
            // TODO: Should be ObjectType::NUMANode but this fails in the C library?
            topo.objects_with_type(&ObjectType::Package)
                .map_or(1, |nodes| nodes.len())
        } else {
            match self.name() {
                "l0318" => 4,
                "b1542" => 2,
                _ => unreachable!("unknown machine"),
            }
        }
    }
}

/// Arguments passed to the run.py script to configure a test.
#[derive(Clone)]
struct RunnerArgs<'a> {
    /// Which machine we should execute on
    machine: Machine,
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
    /// Total persistent memory of the system (in MiB).
    pmem: usize,
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
    timeout: Option<u64>,
    /// Default network interface for QEMU
    nic: &'static str,
    /// Pin QEMU cpu threads
    setaffinity: bool,
    /// Pre-alloc host memory for guest
    prealloc: bool,
    /// Use large-pages for host memory
    large_pages: bool,
    /// Enable gdb
    gdb: bool,
}

#[allow(unused)]
impl<'a> RunnerArgs<'a> {
    fn new(kernel_test: &'a str) -> RunnerArgs {
        let mut args = RunnerArgs {
            machine: Machine::determine(),
            kernel_features: vec![kernel_test],
            user_features: Vec::new(),
            nodes: 0,
            cores: 1,
            memory: 1024,
            pmem: 0,
            cmd: None,
            mods: Vec::new(),
            release: false,
            norun: false,
            qemu_args: Vec::new(),
            timeout: Some(15_000),
            nic: "e1000",
            setaffinity: false,
            prealloc: false,
            large_pages: false,
            gdb: false,
        };

        if cfg!(feature = "prealloc") {
            args = args.prealloc().disable_timeout();
        }

        args
    }

    /// What machine we should run on.
    fn machine(mut self, machine: Machine) -> RunnerArgs<'a> {
        self.machine = machine;
        self
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

    /// Use virtio NIC.
    fn use_virtio(mut self) -> RunnerArgs<'a> {
        self.nic = "virtio";
        self
    }

    /// Use virtio NIC.
    fn use_vmxnet3(mut self) -> RunnerArgs<'a> {
        self.nic = "vmxnet3";
        self
    }

    /// Use e1000 NIC.
    fn use_e1000(mut self) -> RunnerArgs<'a> {
        self.nic = "e1000";
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

    /// How much total system persistent memory (in MiB) that the instance should get.
    ///
    /// The amount is evenly divided among all nodes.
    fn pmem(mut self, mibs: usize) -> RunnerArgs<'a> {
        self.pmem = mibs;
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
        self.timeout = Some(timeout);
        self
    }

    fn disable_timeout(mut self) -> RunnerArgs<'a> {
        self.timeout = None;
        self
    }

    fn setaffinity(mut self) -> RunnerArgs<'a> {
        self.setaffinity = true;
        self
    }

    fn prealloc(mut self) -> RunnerArgs<'a> {
        self.prealloc = true;
        self
    }

    fn large_pages(mut self) -> RunnerArgs<'a> {
        self.large_pages = true;
        self
    }

    fn gdb(mut self) -> RunnerArgs<'a> {
        self.gdb = true;
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

        if self.gdb {
            cmd.push(String::from("--gdb"));
        }

        match &self.machine {
            Machine::Qemu => {
                cmd.push(String::from("--qemu-cores"));
                cmd.push(format!("{}", self.cores));

                cmd.push(String::from("--qemu-nodes"));
                cmd.push(format!("{}", self.nodes));

                cmd.push(String::from("--qemu-memory"));
                cmd.push(format!("{}", self.memory));

                cmd.push(String::from("--qemu-pmem"));
                cmd.push(format!("{}", self.pmem));

                if self.setaffinity {
                    cmd.push(String::from("--qemu-affinity"));
                }
                if self.prealloc {
                    cmd.push(String::from("--qemu-prealloc"));
                }
                if self.large_pages {
                    // TODO: Also register some?
                    // let pages = (self.memory+2) / 2;
                    // sudo bash -c "echo $pages > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
                    // and when done
                    // sudo bash -c "echo 0 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
                    cmd.push(String::from("--qemu-large-pages"));
                }

                // Form arguments for QEMU
                let mut qemu_args: Vec<String> =
                    self.qemu_args.iter().map(|arg| arg.to_string()).collect();
                if !qemu_args.is_empty() {
                    cmd.push(format!("--qemu-settings={}", qemu_args.join(" ")));
                }
            }
            Machine::Baremetal(mname) => {
                cmd.push(format!("--machine={}", mname));
            }
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

fn check_for_exit(expected: ExitStatus, args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
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

fn wait_for_sigterm(args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
    match r {
        Ok(WaitStatus::Signaled(_, SIGTERM, _)) => { /* This is what we expect */ }
        Ok(WaitStatus::Exited(_, code)) => {
            let exit_status: ExitStatus = code.into();
            log_qemu_out(args, output);
            panic!("Unexpected exit code from QEMU: {}", exit_status);
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
fn spawn_nrk(args: &RunnerArgs) -> Result<rexpect::session::PtySession> {
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
    let timeout = if cfg!(feature = "baremetal") {
        // Machine might take very long to boot, so currently
        // we don't use timeouts for baremetal
        Some(8 * 60 * 1000) // 8 Minutes
    } else {
        args.timeout
    };
    spawn_command(o, timeout)
}

/// Spawns a DHCP server on our host
///
/// It uses our dhcpd config and listens on the tap0 interface
/// (that we set up in our run.py script).
fn spawn_dhcpd() -> Result<rexpect::session::PtyReplSession> {
    // apparmor prevents reading of ./tests/dhcpd.conf for dhcpd
    // on Ubuntu, so we make sure it is disabled:
    let o = process::Command::new("sudo")
        .args(&["service", "apparmor", "teardown"])
        .output();
    if o.is_err() {
        match o.unwrap_err().kind() {
            ErrorKind::NotFound => println!("AppArmor not found"),
            _ => panic!("failed to disable apparmor"),
        }
    }
    let _o = process::Command::new("sudo")
        .args(&["killall", "dhcpd"])
        .output()
        .expect("failed to shut down dhcpd");

    // Spawn a bash session for dhcpd, otherwise it seems we
    // can't kill the process since we do not run as root
    let mut b = spawn_bash(Some(45_000))?;
    b.send_line("sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf")?;
    Ok(b)
}

/// Helper function that spawns a UDP receiver socket on the host.
fn spawn_receiver() -> Result<rexpect::session::PtySession> {
    spawn("socat UDP-LISTEN:8889,fork stdout", Some(20_000))
}

/// Helper function that tries to ping the QEMU guest.
fn spawn_ping() -> Result<rexpect::session::PtySession> {
    spawn("ping 172.31.0.10", Some(20_000))
}

#[allow(unused)]
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
    let cmdline = RunnerArgs::new("test-pfault-early").qemu_arg("-d int,cpu_reset");
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

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn s01_pfault() {
    let cmdline = RunnerArgs::new("test-pfault");
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

/// Make sure the general-protection-fault handler works as expected  -- even if
/// we're early on in initialization.
/// In essence a trap should be raised but we can't get a backtrace yet
/// since we don't have memory allocation.
#[test]
fn s00_gpfault_early() {
    let cmdline = RunnerArgs::new("test-gpfault-early").qemu_arg("-d int,cpu_reset");
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

/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
#[test]
fn s01_gpfault() {
    let cmdline = RunnerArgs::new("test-gpfault");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #3  - 0x[0-9a-fA-F]+ - nrk::xmain")?;
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
    let cmdline = RunnerArgs::new("test-alloc");
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
    let cmdline = RunnerArgs::new("test-sse");
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
    let cmdline = RunnerArgs::new("test-time").release();
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
    let cmdline = RunnerArgs::new("test-timer");
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

/// Test that we can initialize the ACPI subsystem and figure out the machine topology.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s02_acpi_topology() {
    let cmdline = &RunnerArgs::new("test-acpi-topology")
        .cores(80)
        .nodes(8)
        .memory(4096)
        .pmem(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");

        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology
/// (a different one than acpi_smoke).
#[cfg(not(feature = "baremetal"))]
#[test]
fn s02_acpi_smoke() {
    let cmdline = &RunnerArgs::new("test-acpi-smoke").cores(2).memory(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");

        output += p.exp_string("ACPI Initialized")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can boot an additional core.
///
/// Utilizes the app core initializtion logic
/// as well as the APIC driver (sending IPIs).
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s02_coreboot_smoke() {
    let cmdline = RunnerArgs::new("test-coreboot-smoke")
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
    let cmdline = RunnerArgs::new("test-coreboot-nrlog")
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

/// Test that we can multiple cores and use the node-replication log to communicate.
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s02_nvdimm_discover() {
    let cmdline = RunnerArgs::new("test-nvdimm-discover")
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
        spawn(format!("gdb {}", binary).as_str(), Some(3_000)).and_then(|p| {
            Ok(PtyReplSession {
                prompt: "(gdb) ".to_string(),
                pty_session: p,
                quit_command: Some("quit".to_string()),
                echo_on: false,
            })
        })
    }

    let cmdline = RunnerArgs::new("test-gdb").gdb().cores(1);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");
        // Wait until kernel is waiting for debugger:
        output += p
            .exp_string("Use `target remote localhost:1234` in gdb to connect.")?
            .as_str();

        // Spawn GDB
        let binary = if cmdline.release {
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
        output += gdb.exp_string("nrk::kcb::BootloaderArguments")?.as_str();

        // Test hardware breakpoints: `hbreak`, `continue`
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("hbreak xmain")?;
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

        // Test `step`, `stepi`
        output += gdb.wait_for_prompt()?.as_str();
        gdb.send_line("step")?;

        // Test `info registers`

        // Test writes to memory

        // Test `continue`

        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

/// Test that we boot up all cores in the system.
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s03_coreboot() {
    let cmdline = &RunnerArgs::new("test-coreboot")
        .cores(32)
        .nodes(4)
        .memory(4096);
    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline).expect("Can't spawn QEMU instance");

        for i in 1..32 {
            // Check that we see all 32 cores booting up
            let expected_output = format!("Core #{} initialized", i);
            output += p.exp_string(expected_output.as_str())?.as_str();
        }

        output += p.exp_eof()?.as_str();
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
        let mut p = spawn_nrk(&cmdline)?;

        output += p.exp_string("print_test OK")?.as_str();
        output += p.exp_string("upcall_test OK")?.as_str();
        output += p.exp_string("map_test OK")?.as_str();
        output += p.exp_string("alloc_test OK")?.as_str();
        output += p.exp_string("scheduler_test OK")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests that the basic vmxnet3 driver in the kernel is functional.
#[cfg(not(feature = "baremetal"))]
#[test]
#[ignore = "flaky make networking stable first"]
fn s03_vmxnet3_smoke() {
    /// Helper function that spawns a UDP echo server on the host
    fn spawn_tcpdump() -> Result<rexpect::session::PtySession> {
        spawn("tcpdump -i tap0 -vvv", Some(25000))
    }

    let cmdline = RunnerArgs::new("test-vmxnet-smoke")
        .timeout(25_000)
        .use_vmxnet3();

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut tcpdump = spawn_tcpdump()?;
        let mut p = spawn_nrk(&cmdline)?;

        output += tcpdump
            .exp_string("172.31.0.10.9999 > 172.31.0.20.5553: [udp sum ok] UDP, length 22")?
            .as_str();

        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests that the vmxnet3 driver is functional together with the smoltcp
/// network stack.
#[cfg(not(feature = "baremetal"))]
#[test]
#[ignore = "flaky make networking stable first"]
fn s03_vmxnet3_smoltcp() {
    fn spawn_socat(port: u16) -> Result<rexpect::session::PtySession> {
        spawn(
            format!("socat - TCP:172.31.0.10:{}", port).as_str(),
            Some(30_000),
        )
    }

    const RANDOM_PAYLOAD: &'static str = std::concat!(
        "wpztnynnlbpcileyvhokhihlbjtbvqlsntqoykjynunjhvjzfgtlukphzgj",
        "arcrclwthsijhtqmutxtnzxxlsvmgnueuaqyvbpsnqsmrhaxcfqlqvzaihv",
        "lkrnfasemjbbcfiwuokjzhhmmraaqilcndvgwqluyxrieudytmrkahhcreb",
        "gwzngglsjsgeyrkywecqgizoklabiifiwjithcdcjvoptaufmiwixnqtmiw",
        "gxqmrtbyugzdmtseqhoijelahbgxaszccughowltxqdnjmgymmvprbgrwlk",
        "swzvirynhhinlausdwcjakofikgqucmhhdkmywxsfarslewqfnrjerumecn",
        "riyliktztgtfouqcznjkwnzbivwqsflhoatumzlylgzvoxxtygkkrkbdusj",
        "ckclfjgxjuaduhdhivhfctabrfqlsgorxueylsmanilqatqagdfjuukhdrm",
        "cfeegpjiylcslveptgmefcpewdxgepgczzzobjiwwncsnambylfavwyabhc",
        "rtdxmiudcdoplgogsczgszmjrvgztxpmrtphwmtezcnpcbzdwknipneyfjy",
        "oessmgegwyohcsyjztgeukfqlvylhpbdoxhoqfbgnuxlyofvizveqtcfvwv",
        "mwowrgxvdhzkhwnbdtgwosmlonepecpmctfqkbhmgzejzwkxizfybtekmkp",
        "mnqworreythicapveoflicgwrlotxquslmwmjckldhoztqlapvtnwdexucs",
        "ytcxngqijnusozjpbkpbemhsjzsvsoyaeghhyhpeykdurcccqqogbuzerdp",
        "xzqihxzfeteoajcccvnxjweqkmdtnrwhbwoxiwhslzzzkochjbzzuwlwajo",
        "cvmgmlliqlegzjtjogdxxzibkxxmycgrqbfvfpojprcrdyqhrejshsilrwb",
        "ptoqenjyuyetcexfmbcajokkaltrhutakohielaupybbycmrjncytbqchgr",
        "ioajegrgemttbadockfiukinstblpsvttltjzecxyahfqybxfabwglxhfvh",
        "qlsxnotbzwtwvcneboxnvzfwxpwasroziyllaecgejabxptlqlwoyuvnhcc",
        "ghrfkrizvpczcwbpcxopepjzfaqdchruyiufzpijjkynbfoaymwntxrrmef",
        "kcgsujicncmmbdibuzwxwfeoyvvoiskrznegkcmauvlcnwtusqyreyteqey",
        "ijzczjmflhvxsasitlppxsbbwwqkbudvbdqbxfltgmusnctctuzgsvwcehm",
        "ypxvqdowwvaozrlexefmmklmhqmonvxwwfwolbrpfvcwrwmpswjaaihzfvh",
        "avhojmnmnvblakpiplsbsouhyrdnmxnluqtqsrzqirgwpnizhrrarpqlaoo",
        "jeabltkqwxfashocdieiomhmhxwcofdlizkrdktkkzaeplthvfvshfwzvhm",
        "vsyzhowinicutacsoqlvnbwukivmrmtkwtxedjehhpbxegwfxtneiprwnns",
        "euzwvaicwxgzbfsaygfublcsugoljmipgawnvwzdficcqmrbtqnbiyfmdwq",
    );

    let cmdline = RunnerArgs::new("test-vmxnet-smoltcp")
        .timeout(30_000)
        .use_vmxnet3();

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string("About to serve sockets!")?.as_str();

        let mut client = spawn_socat(6970)?;
        for i in 0..12 {
            println!("sending pkt = {}", i);
            client.send_line(RANDOM_PAYLOAD)?;
            output += client.exp_string(RANDOM_PAYLOAD)?.as_str();
        }
        client.process.exit()?;
        output += p.exp_eof()?.as_str();

        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Tests the lineup scheduler multi-core ability.
///
/// Makes sure we can request cores and spawn threads on said cores.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s04_userspace_multicore() {
    let machine = Machine::determine();
    let num_cores: usize = machine.max_cores();
    let cmdline = RunnerArgs::new("test-userspace-smp")
        .user_features(&["test-scheduler-smp"])
        .cores(num_cores)
        .memory(2048)
        .timeout(28_000);

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
    let cmdline = RunnerArgs::new("test-userspace")
        .user_feature("test-rump-net")
        .user_feature("rumprt")
        .timeout(20_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_nrk(&cmdline)?;

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
    let cmdline = &RunnerArgs::new("test-userspace")
        .user_feature("test-rump-tmpfs")
        .user_feature("rumprt")
        .timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
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
            panic!("Graphviz invocation failed");
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
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_string(GRAPHVIZ_START)?.as_str();
        graphviz_output = p.exp_string(GRAPHVIZ_END)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
    plot_vspace(&graphviz_output).expect("Can't plot vspace");
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
//#[cfg(not(feature = "baremetal"))]
//#[test]
#[allow(unused)]
fn s05_redis_smoke() {
    let cmdline = RunnerArgs::new("test-userspace")
        .module("rkapps")
        .user_feature("rkapps:redis")
        .cmd("init=redis.bin")
        .timeout(20_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;

        let mut p = spawn_nrk(&cmdline)?;

        // Test that DHCP works:
        dhcp_server.exp_string(DHCP_ACK_MATCH)?;
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

fn redis_benchmark(nic: &'static str, requests: usize) -> Result<rexpect::session::PtySession> {
    fn spawn_bencher(port: u16, requests: usize) -> Result<rexpect::session::PtySession> {
        spawn(
            format!(
                "redis-benchmark -h 172.31.0.10 -p {} -t ping,get,set -n {} -P 30 --csv",
                port, requests
            )
            .as_str(),
            Some(45000),
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
        driver: &'static str,
    }

    let record = Record {
        git_rev: env!("GIT_HASH"),
        ping: ping_tput,
        ping_bulk: ping_bulk_tput,
        set: set_tput,
        get: get_tput,
        driver: nic,
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

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_redis_benchmark_virtio() {
    let cmdline = RunnerArgs::new("test-userspace")
        .module("rkapps")
        .user_feature("rkapps:redis")
        .cmd("init=redis.bin")
        .use_virtio()
        .release()
        .timeout(45_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        let mut dhcp_server = spawn_dhcpd()?;

        // Test that DHCP works:
        output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();
        output += p.exp_string(REDIS_START_MATCH)?.as_str();

        use std::{thread, time};
        thread::sleep(time::Duration::from_secs(9));

        let mut redis_client = redis_benchmark("virtio", 2_000_000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_redis_benchmark_e1000() {
    let cmdline = RunnerArgs::new("test-userspace")
        .module("rkapps")
        .user_feature("rkapps:redis")
        .cmd("init=redis.bin")
        .release()
        .timeout(45_000);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        let mut dhcp_server = spawn_dhcpd()?;

        // Test that DHCP works:
        dhcp_server.exp_string(DHCP_ACK_MATCH)?;
        output += p.exp_string(REDIS_START_MATCH)?.as_str();

        use std::{thread, time};
        thread::sleep(time::Duration::from_secs(9));

        let mut redis_client = redis_benchmark("e1000", 2_000_000)?;

        dhcp_server.send_control('c')?;
        redis_client.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    wait_for_sigterm(&cmdline, qemu_run(), output);
}

#[test]
fn s06_vmops_benchmark() {
    let machine = Machine::determine();
    let threads = machine.thread_defaults_uniform();

    let file_name = "vmops_benchmark.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("bench-vmops")
            .cores(machine.max_cores())
            .setaffinity()
            .timeout(12_000 + cores as u64 * 3000)
            .release()
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(10 * 1024);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

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
fn s06_shootdown_simple() {
    let machine = Machine::determine();
    let threads = machine.thread_defaults_uniform();

    let file_name = "tlb_shootdown.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new("test-shootdown-simple")
            .module("init")
            .cores(cores)
            .setaffinity()
            .timeout(12_000 + cores as u64 * 3000)
            .release()
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(8192);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            let max_numa_nodes = cmdline.machine.max_numa_nodes();
            cmdline = cmdline.nodes(max_numa_nodes);
        }

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like
            // `init::vmops: 1,maponly,1,4096,10000,1000,634948`
            // write them to a CSV file
            let expected_lines = 1;
            for _i in 0..expected_lines {
                let (prev, matched) = p.exp_regex(r#"shootdown-simple,(\d+),(\d+)"#)?;
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
                    let row = "git_rev,name,cores,shootdown_duration_ns\n";
                    let r = csv_file.write(row.as_bytes());
                    assert!(r.is_ok());
                }

                let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write(matched.as_bytes());
                assert!(r.is_ok());
                let r = csv_file.write("\n".as_bytes());
                assert!(r.is_ok());
            }

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(), output);
    }
}

#[test]
fn s06_vmops_latency_benchmark() {
    let machine = Machine::determine();
    let threads = machine.thread_defaults_uniform();

    let file_name = "vmops_benchmark_latency.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("bench-vmops")
            .user_feature("latency")
            .cores(machine.max_cores())
            .setaffinity()
            .timeout(25_000 + cores as u64 * 100_000)
            .release()
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(24 * 1024);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like:
            // "Latency percentiles [ns]: maponly,2,4096,1092,1351,1939,3111,4711,9864,2089812"
            // and writes them to a CSV file
            let (prev, matched) =
                    p.exp_regex(r#"init::vmops: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
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
                let row = "git_rev,benchmark,ncores,memsize,p1,p25,p50,p75,p99,p999,p100\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched
                .split("init::vmops: Latency percentiles: ")
                .collect();
            assert!(parts.len() >= 2);
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s06_vmops_unmaplat_latency_benchmark() {
    let machine = Machine::determine();
    let threads = machine.thread_defaults_uniform();

    let file_name = "vmops_unmaplat_benchmark_latency.csv";
    let _r = std::fs::remove_file(file_name);

    for &cores in threads.iter() {
        let kernel_cmdline = format!("initargs={}", cores);
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("init")
            .user_feature("bench-vmops-unmaplat")
            .user_feature("latency")
            .cores(machine.max_cores())
            .setaffinity()
            .timeout(35_000 + cores as u64 * 100_000)
            .release()
            .cmd(kernel_cmdline.as_str());

        if cfg!(feature = "smoke") {
            cmdline = cmdline.user_feature("smoke").memory(18192);
        } else {
            cmdline = cmdline.memory(48 * 1024);
        }

        if cfg!(feature = "smoke") && cores > 2 {
            cmdline = cmdline.nodes(2);
        } else {
            cmdline = cmdline.nodes(machine.max_numa_nodes());
        }

        let mut output = String::new();
        let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;

            // Parse lines like:
            // "Latency percentiles [ns]: maponly,2,4096,1092,1351,1939,3111,4711,9864,2089812"
            // and writes them to a CSV file
            let (prev, matched) =
                    p.exp_regex(r#"init::vmops::unmaplat: Latency percentiles: (.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#)?;
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
                let row = "git_rev,benchmark,ncores,memsize,p1,p25,p50,p75,p99,p999,p100\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched
                .split("init::vmops::unmaplat: Latency percentiles: ")
                .collect();
            assert!(parts.len() >= 2);
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write(parts[1].as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            output += p.exp_eof()?.as_str();
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(cores), output);
    }
}

#[test]
fn s06_fxmark_benchmark() {
    // benchmark naming convention = nameXwrite - mixX10 is - mix benchmark for 10% writes.
    let benchmarks = vec!["mixX0", "mixX10", "mixX100"];
    let num_microbenchs = benchmarks.len() as u64;

    let machine = Machine::determine();
    let threads = machine.thread_defaults_low_mid_high();

    let file_name = "fxmark_benchmark.csv";
    let _ignore = std::fs::remove_file(file_name);

    fn open_files(benchmark: &str, max_cores: usize, nodes: usize) -> Vec<usize> {
        if benchmark.contains("mix") {
            if cfg!(feature = "smoke") {
                vec![1]
            } else {
                vec![1, max_cores / nodes]
            }
        } else {
            vec![0]
        }
    }

    for benchmark in benchmarks {
        let open_files: Vec<usize> =
            open_files(benchmark, machine.max_cores(), machine.max_numa_nodes());
        for &cores in threads.iter() {
            for &of in open_files.iter() {
                let kernel_cmdline = format!("initargs={}X{}X{}", cores, of, benchmark);
                let mut cmdline = RunnerArgs::new("test-userspace-smp")
                    .module("init")
                    .user_feature("fxmark")
                    .memory(1024)
                    .timeout(num_microbenchs * (25_000 + cores as u64 * 1000))
                    .cores(machine.max_cores())
                    .setaffinity()
                    .cmd(kernel_cmdline.as_str())
                    .release();

                if cfg!(feature = "smoke") {
                    cmdline = cmdline.user_feature("smoke").memory(8192);
                } else {
                    cmdline = cmdline.memory(core::cmp::max(49152, cores * 512));
                }

                if cfg!(feature = "smoke") && cores > 2 {
                    cmdline = cmdline.nodes(2);
                } else {
                    cmdline = cmdline.nodes(machine.max_numa_nodes());
                }

                let mut output = String::new();
                let mut qemu_run = |_with_cores: usize| -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline)?;

                    // Parse lines like
                    // `init::fxmark: 1,fxmark,2,2048,10000,4000,1863272`
                    // write them to a CSV file
                    let expected_lines = if cfg!(feature = "smoke") {
                        1
                    } else {
                        cores * 10
                    };

                    for _i in 0..expected_lines {
                        let (prev, matched) = p.exp_regex(
                            r#"init::fxmark: (\d+),(.*),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"#,
                        )?;
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
                         "git_rev,thread_id,benchmark,ncores,write_ratio,open_files,duration_total,duration,operations\n";
                            let r = csv_file.write(row.as_bytes());
                            assert!(r.is_ok());
                        }

                        let parts: Vec<&str> = matched.split("init::fxmark: ").collect();
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
    }
}

/// Tests that basic file-system support is functional.
///
/// This tests various file-system systemcalls such as:
///  * File open, close
///  * File read, write
///  * File getinfo
///  * All the above operations with invalid userspace pointers
#[test]
fn s06_test_fs() {
    let cmdline = RunnerArgs::new("test-userspace-smp")
        .module("init")
        .user_feature("test-fs")
        .release()
        .timeout(20_000);
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
fn s06_test_fs_prop() {
    let cmdline = RunnerArgs::new("test-userspace")
        .module("init")
        .user_feature("test-fs-prop")
        .release()
        .timeout(120_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        p.exp_string("fs_prop_test OK")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

fn memcached_benchmark(
    driver: &'static str,
    cores: usize,
    duration: usize,
) -> Result<rexpect::session::PtySession> {
    fn spawn_memaslap(duration: usize) -> Result<rexpect::session::PtySession> {
        spawn(
            format!("memaslap -s 172.31.0.10 -t {}s -S 10s", duration).as_str(),
            Some(25000),
        )
    }
    let mut memaslap = spawn_memaslap(duration)?;

    // Parse this:
    // ```
    // Get Statistics (978827 events)
    // Min:        55
    // Max:      4776
    // Avg:       146
    // Geo:    145.18
    // Std:     32.77
    //
    // Set Statistics (108766 events)
    // Min:        57
    // Max:      4649
    // Avg:       147
    // Geo:    145.91
    // Std:     30.20
    // ```

    let _before = memaslap.exp_string(r#"Get Statistics ("#)?;
    let (_before, get_total) = memaslap.exp_regex(r#"([0-9]+)"#)?;

    let (_before, _line) = memaslap.exp_regex(r#"Min:\s+"#)?;
    let (_before, get_min_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Max:\s+"#)?;
    let (_before, get_max_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Avg:\s+"#)?;
    let (_before, get_avg_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Std:\s+"#)?;
    let (_before, get_std_us) = memaslap.exp_regex(r#"(\d+)"#)?;

    let get_total: usize = get_total.parse().unwrap_or(404);
    let get_min_us: usize = get_min_us.parse().unwrap_or(404);
    let get_max_us: usize = get_max_us.parse().unwrap_or(404);
    let get_avg_us: usize = get_avg_us.parse().unwrap_or(404);
    let get_std_us: usize = get_std_us.parse().unwrap_or(404);

    let _before = memaslap.exp_string(r#"Set Statistics ("#)?;
    let (_before, set_total) = memaslap.exp_regex(r#"([0-9]+)"#)?;

    let (_before, _line) = memaslap.exp_regex(r#"Min:\s+"#)?;
    let (_before, set_min_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Max:\s+"#)?;
    let (_before, set_max_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Avg:\s+"#)?;
    let (_before, set_avg_us) = memaslap.exp_regex(r#"(\d+)"#)?;
    let (_before, _line) = memaslap.exp_regex(r#"Std:\s+"#)?;
    let (_before, set_std_us) = memaslap.exp_regex(r#"(\d+)"#)?;

    let set_total: usize = set_total.parse().unwrap_or(404);
    let set_min_us: usize = set_min_us.parse().unwrap_or(404);
    let set_max_us: usize = set_max_us.parse().unwrap_or(404);
    let set_avg_us: usize = set_avg_us.parse().unwrap_or(404);
    let set_std_us: usize = set_std_us.parse().unwrap_or(404);

    // Append parsed results to a CSV file
    let file_name = "memcached_benchmark.csv";
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

    #[derive(Serialize, Debug, Copy, Clone)]
    struct Record {
        git_rev: &'static str,
        cores: usize,
        duration: usize,
        driver: &'static str,
        get_total: usize,
        get_min_us: usize,
        get_max_us: usize,
        get_avg_us: usize,
        get_std_us: usize,
        set_total: usize,
        set_min_us: usize,
        set_max_us: usize,
        set_avg_us: usize,
        set_std_us: usize,
    }

    let record = Record {
        git_rev: env!("GIT_HASH"),
        cores,
        duration,
        driver,
        get_total,
        get_min_us,
        get_max_us,
        get_avg_us,
        get_std_us,
        set_total,
        set_min_us,
        set_max_us,
        set_avg_us,
        set_std_us,
    };

    wtr.serialize(record).expect("Can't write results");

    Ok(memaslap)
}

#[cfg(not(feature = "baremetal"))]
#[test]
fn s06_memcached_benchmark() {
    let max_cores = 4;
    let threads = if cfg!(feature = "smoke") {
        vec![1]
    } else {
        vec![1, 2, 4]
    };

    let file_name = "memcached_benchmark.csv";
    let _r = std::fs::remove_file(file_name);

    for nic in &["virtio", "e1000"] {
        for thread in threads.iter() {
            let kernel_cmdline = format!("init=memcached.bin initargs={}", *thread);
            let cmdline = RunnerArgs::new("test-userspace-smp")
                .module("rkapps")
                .user_feature("rkapps:memcached")
                .memory(8192)
                .timeout(25_000)
                .cores(max_cores)
                .nodes(1)
                .setaffinity()
                .cmd(kernel_cmdline.as_str())
                .release();

            let cmdline = match *nic {
                "virtio" => cmdline.use_virtio(),
                "e1000" => cmdline.use_e1000(),
                _ => unimplemented!("NIC type unknown"),
            };

            let output = String::new();
            let qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline)?;
                let mut dhcp_server = spawn_dhcpd()?;
                dhcp_server.exp_string(DHCP_ACK_MATCH)?;

                std::thread::sleep(std::time::Duration::from_secs(6));
                let mut memaslap = memcached_benchmark(nic, *thread, 10)?;

                dhcp_server.send_control('c')?;
                memaslap.process.kill(SIGTERM)?;

                p.process.kill(SIGTERM)
            };

            wait_for_sigterm(&cmdline, qemu_run(), output);
        }
    }
}

#[test]
fn s06_leveldb_benchmark() {
    let machine = Machine::determine();
    let threads: Vec<usize> = machine
        .thread_defaults_uniform()
        .into_iter()
        // Throw out everything above 28 since we have some non-deterministic
        // bug on larger machines that leads to threads calling sched_yield and
        // no readrandom is performed...
        .filter(|&t| t <= 28)
        .collect();

    // level-DB arguments
    let (reads, num, val_size) = if cfg!(feature = "smoke") {
        (10_000, 5_000, 4096)
    } else {
        (100_000, 50_000, 65535)
    };

    let file_name = "leveldb_benchmark.csv";
    let _r = std::fs::remove_file(file_name);

    for thread in threads.iter() {
        let kernel_cmdline = format!(
            r#"init=dbbench.bin initargs={} appcmd='--threads={} --benchmarks=fillseq,readrandom --reads={} --num={} --value_size={}'"#,
            *thread, *thread, reads, num, val_size
        );
        let mut cmdline = RunnerArgs::new("test-userspace-smp")
            .module("rkapps")
            .user_feature("rkapps:leveldb-bench")
            .timeout(180_000)
            .cores(machine.max_cores())
            .nodes(2)
            .use_virtio()
            .setaffinity()
            .cmd(kernel_cmdline.as_str())
            .release();

        if cfg!(feature = "smoke") {
            cmdline = cmdline.memory(8192);
        } else {
            cmdline = cmdline.memory(80_000);
        }

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&cmdline)?;
            let mut dhcp_server = spawn_dhcpd()?;
            output += dhcp_server.exp_string(DHCP_ACK_MATCH)?.as_str();

            let (prev, matched) = p.exp_regex(r#"readrandom(.*)"#)?;
            println!("{}", matched);
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
                let row = "git_rev,benchmark,ncores,reads,num,val_size,operations\n";
                let r = csv_file.write(row.as_bytes());
                assert!(r.is_ok());
            }

            let parts: Vec<&str> = matched.split("ops/sec").collect();
            let mut parts: Vec<&str> = parts[0].split(" ").collect();
            parts.pop();
            let r = csv_file.write(format!("{},", env!("GIT_HASH")).as_bytes());
            assert!(r.is_ok());
            let out = format!(
                "readrandom,{},{},{},{},{}",
                *thread,
                reads,
                num,
                val_size,
                parts.last().unwrap()
            );
            let r = csv_file.write(out.as_bytes());
            assert!(r.is_ok());
            let r = csv_file.write("\n".as_bytes());
            assert!(r.is_ok());

            // cleanup
            dhcp_server.send_control('c')?;
            p.process.kill(SIGTERM)?;
            p.process.exit()
        };

        check_for_successful_exit(&cmdline, qemu_run(), output);
    }
}

/// Tests that basic pmem allocation support is functional.
/// TODO: Store persistent data durably and test it.
#[test]
fn s06_pmem_alloc() {
    let machine = Machine::determine();
    let cmdline = RunnerArgs::new("test-userspace-smp")
        .module("init")
        .user_feature("test-pmem-alloc")
        .nodes(machine.max_numa_nodes())
        .cores(machine.max_cores())
        .release()
        .memory(8192)
        .pmem(2048)
        .timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        output += p.exp_string("pmem_alloc OK")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}
