// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;

use crate::builder::{BuildArgs, Built, Machine};
use crate::ExitStatus;

/// Arguments passed to the run.py script to configure a test.
#[derive(Clone)]
pub struct RunnerArgs<'a> {
    /// Which machine we should execute on
    pub machine: Machine,
    /// Any arguments used during the build of kernel/user-space
    pub build_args: BuildArgs<'a>,
    /// Kernel test (aka xmain function) that should be executed.
    kernel_test: &'a str,
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
    /// If true don't run, just compile.
    norun: bool,
    /// If true don't build, just run.
    nobuild: bool,
    /// Parameters to add to the QEMU command line
    qemu_args: Vec<&'a str>,
    /// Timeout in ms
    pub timeout: Option<u64>,
    /// Default network interface for QEMU
    nic: &'static str,
    /// Pin QEMU cpu threads
    setaffinity: bool,
    /// Pre-alloc host memory for guest
    prealloc: bool,
    /// Use large-pages for host memory
    large_pages: bool,
    /// Enable gdb for the kernel
    kgdb: bool,
    /// shared memory size.
    shmem_size: usize,
    /// Shared memory file path.
    shmem_path: String,
    /// Tap interface
    tap: Option<String>,
    /// Number of workers
    workers: Option<usize>,
    /// Configure network only
    network_only: bool,
    /// Do not configure the network
    no_network_setup: bool,
}

#[allow(unused)]
impl<'a> RunnerArgs<'a> {
    pub fn new_with_build(kernel_test: &'a str, built: &'a Built<'a>) -> RunnerArgs<'a> {
        let mut args = RunnerArgs {
            machine: Machine::determine(),
            kernel_test,
            build_args: built.with_args.clone(),
            nodes: 0,
            cores: 1,
            memory: 1024,
            pmem: 0,
            cmd: None,
            norun: false,
            nobuild: false,
            qemu_args: Vec::new(),
            timeout: Some(15_000),
            nic: "e1000",
            setaffinity: false,
            prealloc: false,
            large_pages: false,
            kgdb: false,
            shmem_size: 0,
            shmem_path: String::new(),
            tap: None,
            workers: None,
            network_only: false,
            no_network_setup: false,
        };

        if cfg!(feature = "prealloc") {
            args = args.prealloc().disable_timeout();
        }

        args
    }

    pub fn new(kernel_test: &'a str) -> RunnerArgs {
        let mut args = RunnerArgs {
            machine: Machine::determine(),
            kernel_test,
            build_args: Default::default(),
            nodes: 0,
            cores: 1,
            memory: 1024,
            pmem: 0,
            cmd: None,
            norun: false,
            nobuild: false,
            qemu_args: Vec::new(),
            timeout: Some(15_000),
            nic: "e1000",
            setaffinity: false,
            prealloc: false,
            large_pages: false,
            kgdb: false,
            shmem_size: 0,
            shmem_path: String::new(),
            tap: None,
            workers: None,
            network_only: false,
            no_network_setup: false,
        };

        if cfg!(feature = "prealloc") {
            args = args.prealloc().disable_timeout();
        }

        args
    }

    /// What machine we should run on.
    pub fn machine(mut self, machine: Machine) -> RunnerArgs<'a> {
        self.machine = machine;
        self
    }

    /// How many NUMA nodes QEMU should simulate.
    pub fn nodes(mut self, nodes: usize) -> RunnerArgs<'a> {
        self.nodes = nodes;
        self
    }

    /// Use virtio NIC.
    pub fn use_virtio(mut self) -> RunnerArgs<'a> {
        self.nic = "virtio-net-pci";
        self
    }

    /// Use virtio NIC.
    pub fn use_vmxnet3(mut self) -> RunnerArgs<'a> {
        self.nic = "vmxnet3";
        self
    }

    /// Use e1000 NIC.
    pub fn use_e1000(mut self) -> RunnerArgs<'a> {
        self.nic = "e1000";
        self
    }

    /// How many cores QEMU should simulate.
    pub fn cores(mut self, cores: usize) -> RunnerArgs<'a> {
        self.cores = cores;
        self
    }

    /// How much total system memory (in MiB) that the instance should get.
    ///
    /// The amount is evenly divided among all nodes.
    pub fn memory(mut self, mibs: usize) -> RunnerArgs<'a> {
        self.memory = mibs;
        self
    }

    /// How much total system persistent memory (in MiB) that the instance should get.
    ///
    /// The amount is evenly divided among all nodes.
    pub fn pmem(mut self, mibs: usize) -> RunnerArgs<'a> {
        self.pmem = mibs;
        self
    }

    /// Command line passed to the kernel.
    pub fn cmd(mut self, cmd: &'a str) -> RunnerArgs<'a> {
        self.cmd = Some(cmd);
        self
    }

    /// Don't run, just build.
    pub fn norun(mut self) -> RunnerArgs<'a> {
        self.norun = true;
        self
    }

    /// Don't build, just run.
    pub fn nobuild(mut self) -> RunnerArgs<'a> {
        self.nobuild = true;
        self
    }

    /// Which arguments we want to add to QEMU.
    pub fn qemu_args(mut self, args: &[&'a str]) -> RunnerArgs<'a> {
        self.qemu_args.extend_from_slice(args);
        self
    }

    /// Adds an argument to QEMU.
    pub fn qemu_arg(mut self, arg: &'a str) -> RunnerArgs<'a> {
        self.qemu_args.push(arg);
        self
    }

    pub fn timeout(mut self, timeout: u64) -> RunnerArgs<'a> {
        self.timeout = Some(timeout);
        self
    }

    pub fn disable_timeout(mut self) -> RunnerArgs<'a> {
        self.timeout = None;
        self
    }

    pub fn setaffinity(mut self) -> RunnerArgs<'a> {
        self.setaffinity = true;
        self
    }

    pub fn prealloc(mut self) -> RunnerArgs<'a> {
        self.prealloc = true;
        self
    }

    pub fn large_pages(mut self) -> RunnerArgs<'a> {
        self.large_pages = true;
        self
    }

    pub fn kgdb(mut self) -> RunnerArgs<'a> {
        self.kgdb = true;
        self
    }

    pub fn shmem_size(mut self, mibs: usize) -> RunnerArgs<'a> {
        self.shmem_size = mibs;
        self
    }

    pub fn shmem_path(mut self, path: &str) -> RunnerArgs<'a> {
        self.shmem_path = String::from(path);
        self
    }

    pub fn tap(mut self, tap: &str) -> RunnerArgs<'a> {
        self.tap = Some(String::from(tap));
        self
    }

    pub fn workers(mut self, workers: usize) -> RunnerArgs<'a> {
        self.workers = Some(workers);
        self
    }

    pub fn network_only(mut self) -> RunnerArgs<'a> {
        self.network_only = true;
        self
    }

    pub fn no_network_setup(mut self) -> RunnerArgs<'a> {
        self.no_network_setup = true;
        self
    }

    /// Converts the RunnerArgs to a run.py command line invocation.
    pub fn as_cmd(&'a self) -> Vec<String> {
        // Figure out log-level
        let log_level = match std::env::var("RUST_LOG") {
            Ok(lvl) if lvl == "debug" => "debug",
            Ok(lvl) if lvl == "trace" => "trace",
            Ok(lvl) if lvl == "warn" => "warn",
            Ok(lvl) if lvl == "error" => "error",
            Ok(lvl) if lvl == "info" => "info",
            _ => "info",
        };

        // Start with cmdline from build
        let mut cmd = self.build_args.as_cmd();

        // Add net subcommand, will only use if needed
        let mut net_cmd = Vec::<String>::new();
        net_cmd.push(String::from("net"));

        cmd.push(String::from("--cmd"));
        cmd.push(format!(
            "log={} test={} {}",
            log_level,
            self.kernel_test,
            self.cmd.unwrap_or("")
        ));
        cmd.push(String::from("--nic"));
        cmd.push(String::from(self.nic));

        match &self.machine {
            Machine::Qemu => {
                cmd.push(String::from("--qemu-cores"));
                cmd.push(format!("{}", self.cores));

                cmd.push(String::from("--qemu-nodes"));
                cmd.push(format!("{}", self.nodes));

                cmd.push(String::from("--qemu-memory"));
                cmd.push(format!("{}", self.memory));

                if self.pmem > 0 {
                    cmd.push(String::from("--qemu-pmem"));
                    cmd.push(format!("{}", self.pmem));
                }

                if self.shmem_size > 0 {
                    cmd.push(String::from("--qemu-ivshmem"));
                    cmd.push(format!("{}", self.shmem_size));
                }

                if !self.shmem_path.is_empty() {
                    cmd.push(String::from("--qemu-shmem-path"));
                    cmd.push(format!("{}", self.shmem_path));
                }

                if self.tap.is_some() {
                    cmd.push(String::from("--tap"));
                    cmd.push(format!("{}", self.tap.as_ref().unwrap()));
                }

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

                // TODO: this is a bit broken, because no regular arguments can come after a
                // command to a python argparse subparser. To make sure parsing order doesn't matter,
                // create as a separate 'net_cmd' variable, and add it to the end later (even though it is qemu specific)
                if self.workers.is_some() {
                    net_cmd.push(String::from("--workers"));
                    net_cmd.push(format!("{}", self.workers.unwrap()));
                }

                if self.network_only {
                    net_cmd.push(String::from("--network-only"));
                }

                if self.no_network_setup {
                    net_cmd.push(String::from("--no-network-setup"));
                }
            }
            Machine::Baremetal(mname) => {
                cmd.push(format!("--machine={}", mname));
            }
        }

        if self.kgdb {
            cmd.push(String::from("--kgdb"));
        }

        // Don't run qemu, just build?
        if self.norun {
            cmd.push(String::from("--norun"));
        }

        // Don't run qemu, just build?
        if self.nobuild {
            cmd.push(String::from("--nobuild"));
        }

        // Considered empty if only subcommand start ('net') is only thing in array
        if net_cmd.len() > 1 {
            cmd.append(&mut net_cmd);
        }

        cmd
    }
}

pub fn check_for_successful_exit(args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
    check_for_exit(ExitStatus::Success, args, r, output);
}

pub fn log_qemu_out(args: &RunnerArgs, output: String) {
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

pub fn check_for_exit(
    expected: ExitStatus,
    args: &RunnerArgs,
    r: Result<WaitStatus>,
    output: String,
) {
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

pub fn wait_for_sigterm(args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
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
