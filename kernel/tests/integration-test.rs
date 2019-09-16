#![feature(vec_remove_item)]

extern crate rexpect;
#[macro_use]
extern crate matches;

use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::process;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::session::spawn_command;
use rexpect::{spawn, spawn_bash};

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
            ExitStatus::Unknown(_) => {
                "Unknown: Kernel exited with unknown error status... Update the code!"
            }
        };

        write!(f, "{}", desc)
    }
}

/// Arguments passed to the run.sh script to configure a test.
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
}

#[allow(unused)]
impl<'a> RunnerArgs<'a> {
    fn new(kernel_test: &'a str) -> RunnerArgs {
        RunnerArgs {
            kernel_features: vec![kernel_test],
            user_features: Vec::new(),
            nodes: 1,
            cores: 1,
            memory: 1024,
            cmd: None,
            mods: Vec::new(),
            release: false,
            norun: false,
            qemu_args: Vec::new(),
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

    /// Converts the RunnerArgs to a run.sh command line invocation.
    fn as_cmd(&'a self) -> Vec<String> {
        use std::ops::Add;
        // Add features for build
        let kernel_features = String::from(self.kernel_features.join(","));
        let user_features = String::from(self.user_features.join(","));

        let mut cmd = vec![
            String::from("run.sh"),
            String::from("--kfeatures"),
            kernel_features,
            String::from("--cmd"),
            String::from("log=info"),
        ];

        match self.user_features.is_empty() {
            false => {
                cmd.push(String::from("--ufeatures"));
                cmd.push(user_features);
            }
            true => {}
        };

        // Form arguments for QEMU
        cmd.push(String::from("--qemu"));
        let mut qemu_args: Vec<String> = self.qemu_args.iter().map(|arg| arg.to_string()).collect();
        qemu_args.push(format!("-m {}M", self.memory));

        if self.nodes > 1 || self.cores > 1 {
            if self.nodes > 1 {
                for node in 0..self.nodes {
                    // Divide memory equally across cores
                    let mem_per_node = self.memory / self.nodes;
                    qemu_args.push(format!("-numa node,mem={}M,nodeid={}", mem_per_node, node));
                    // 1:1 mapping of sockets to cores
                    qemu_args.push(format!("-numa cpu,node-id={},socket-id={}", node, node));
                }
            }

            if self.cores > 1 {
                let sockets = self.nodes;
                qemu_args.push(format!(
                    "-smp {},sockets={},maxcpus={}",
                    self.cores, sockets, self.cores
                ));
            }
        }
        cmd.push(String::from(qemu_args.join(" ")));

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
    check_for_exit(ExitStatus::Success, args, r, output)
}

fn check_for_exit(expected: ExitStatus, args: &RunnerArgs, r: Result<WaitStatus>, output: String) {
    fn log_qemu_out(args: &RunnerArgs, output: String) {
        if !output.is_empty() {
            println!("\n===== QEMU LOG =====");
            println!("{}", output);
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

        println!("We invoked: bash {}", quoted_cmd);
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

    let o = process::Command::new("bash")
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

    let mut o = process::Command::new("bash");
    o.args(args.as_cmd());

    //eprintln!("Invoke QEMU: {:?}", o);
    spawn_command(o, Some(15000))
}

/// Spawns a DHCP server on our host
///
/// It uses our dhcpd config and listens on the tap0 interface
/// (that we set up in our run.sh script).
fn spawn_dhcpd() -> Result<rexpect::session::PtyBashSession> {
    // apparmor prevents reading of ./tests/dhcpd.conf for dhcpd
    // on Ubuntu, so we make sure it is disabled:
    let _o = process::Command::new("sudo")
        .args(&["service", "apparmor", "teardown"])
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

/// Make sure exiting the kernel works.
///
/// We have a special ioport that we use to signal the exit to
/// qemu and some parsing logic to read the exit code
/// and communicate if our tests passed or failed.
#[test]
fn exit() {
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

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn pfault() {
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

/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
#[test]
fn gpfault() {
    let cmdline = RunnerArgs::new("test-gpfault");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #2  - 0x[0-9a-fA-F]+ - bespin::xmain")?;
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

/// Make sure we can do kernel memory allocations.
///
/// This smoke tests the physical memory allocator
/// and the global allocator integration.
#[test]
fn alloc() {
    let cmdline = RunnerArgs::new("test-alloc");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("small allocations work.")?;
        p.exp_string("large allocations work.")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that makes use of SSE in kernel-space and see if it works.AsMut
///
/// Tests that we have correctly set-up the hardware to deal with floating
/// point.
#[test]
fn sse() {
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

/// Tests the scheduler (in kernel-space).
#[test]
fn scheduler() {
    let cmdline = RunnerArgs::new("test-scheduler");
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline)?;
        p.exp_string("lwt2 ThreadId(1)")?;
        p.exp_string("lwt1 ThreadId(0)")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology.
#[test]
fn acpi_topology() {
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

    check_for_successful_exit(&cmdline, qemu_run(), output)
}

/// Test that we can initialize the ACPI subsystem and figure out the machine topology
/// (a different one than acpi_smoke).
#[test]
fn acpi_smoke() {
    let cmdline = &RunnerArgs::new("test-acpi-smoke").cores(2).memory(1024);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&cmdline).expect("Can't spawn QEMU instance");

        p.exp_string("ACPI Initialized")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output)
}

/// Test that we can boot an additional core.
///
/// Utilizes the app core initializtion logic
/// as well as the APIC driver (sending IPIs).
#[test]
fn coreboot_smoke() {
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

/// Tests that basic user-space support is functional.
///
/// This tests various user-space components such as:
///  * process loading
///  * system calls (printing, mem. mgmt.)
///  * user-space scheduling and upcalls
///  * BSD libOS in user-space
#[test]
fn userspace_smoke() {
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

/// Tests that user-space networking is functional.
///
/// This tests various user-space components such as:
///  * BSD libOS network stack
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
///
#[test]
fn userspace_rumprt_net() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_bespin(&RunnerArgs::new("test-userspace").user_feature("test-rump-net"))?;

        // Test that DHCP works:
        dhcp_server.exp_string("DHCPACK on 172.31.0.10 to 52:54:00:12:34:56 (btest) via tap0")?;

        // Test that sendto works:
        // Currently swallows first packet (see also: https://github.com/rumpkernel/rumprun/issues/131)
        //receiver.exp_string("pkt 1")?;
        receiver.exp_string("pkt 2")?;
        receiver.exp_string("pkt 3")?;
        receiver.exp_string("pkt 4")?;

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
fn userspace_rumprt_fs() {
    let cmdline = &RunnerArgs::new("test-userspace").user_feature("test-rump-tmpfs");
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
