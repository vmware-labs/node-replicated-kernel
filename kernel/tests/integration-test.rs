#![feature(vec_remove_item)]

extern crate rexpect;
#[macro_use]
extern crate matches;

use std::io::{self, Write};
use std::process;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::session::spawn_command;
use rexpect::{spawn, spawn_bash};

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
}

#[allow(unused)]
impl<'a> RunnerArgs<'a> {
    fn new(kernel_test: &str) -> RunnerArgs {
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
        }
    }

    /// What cargo features should be passed to the kernel build.
    fn kernel_features(&'a mut self, kernel_features: &[&'a str]) -> &'a mut RunnerArgs {
        self.kernel_features.extend_from_slice(kernel_features);
        self
    }

    /// Add a cargo feature to the kernel build.
    fn kernel_feature(&'a mut self, kernel_feature: &'a str) -> &'a mut RunnerArgs {
        self.kernel_features.push(kernel_feature);
        self
    }

    /// What cargo features should be passed to the user-space modules build.
    fn user_features(&'a mut self, user_features: &[&'a str]) -> &'a mut RunnerArgs {
        self.user_features.extend_from_slice(user_features);
        self
    }

    /// Add a cargo feature to the user-space modules build.
    fn user_feature(&'a mut self, user_feature: &'a str) -> &'a mut RunnerArgs {
        self.user_features.push(user_feature);
        self
    }

    /// How many NUMA nodes QEMU should simulate.
    fn nodes(&'a mut self, nodes: usize) -> &'a mut RunnerArgs {
        self.nodes = nodes;
        self
    }

    /// How many cores QEMU should simulate.
    fn cores(&'a mut self, cores: usize) -> &'a mut RunnerArgs {
        self.cores = cores;
        self
    }

    /// Command line passed to the kernel.
    fn cmd(&'a mut self, cmd: &'a str) -> &'a mut RunnerArgs {
        self.cmd = Some(cmd);
        self
    }

    /// Which user-space modules we want to include.
    fn modules(&'a mut self, mods: &[&'a str]) -> &'a mut RunnerArgs {
        self.mods.extend_from_slice(mods);
        self
    }

    /// Adds a user-space module to the build and deployment.
    fn module(&'a mut self, module: &'a str) -> &'a mut RunnerArgs {
        self.mods.push(module);
        self
    }

    /// Do a release build.
    fn release(&'a mut self) -> &'a mut RunnerArgs {
        self.release = true;
        self
    }

    /// Don't run, just build.
    fn norun(&'a mut self) -> &'a mut RunnerArgs {
        self.norun = true;
        self
    }

    /// Converts the RunnerArgs to a run.sh command line invocation.
    fn as_cmd(&'a self) -> Vec<String> {
        use std::ops::Add;

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

        if self.nodes > 1 || self.cores > 1 {
            cmd.push(String::from("--qemu"));
            let mut qemu_args = String::new();

            if self.nodes > 1 {
                for node in 0..self.nodes {
                    // Divide memory equally across cores
                    let mem_per_node = self.memory / self.nodes;
                    qemu_args.push_str(
                        format!("-numa node,mem={},nodeid={} ", mem_per_node, node).as_str(),
                    );
                    // 1:1 mapping of sockets to cores
                    qemu_args.push_str(
                        format!("-numa cpu,node-id={},socket-id={} ", node, node).as_str(),
                    );
                }
            }

            if self.cores > 1 {
                let sockets = self.nodes;
                qemu_args.push_str(
                    format!(
                        "-smp {},sockets={},maxcpus={}",
                        self.cores, sockets, self.cores
                    )
                    .as_str(),
                );

                cmd.push(qemu_args);
            }
        }

        match self.norun {
            false => {}
            true => {
                cmd.push(String::from("--norun"));
            }
        };

        cmd
    }
}

fn check_for_successful_exit(r: Result<WaitStatus>, output: String) {
    match r {
        Ok(WaitStatus::Exited(_, exit_status)) => {
            if exit_status != 0 {
                println!("\n===== QEMU LOG =====");
                println!("{}", output);
                println!("===== END QEMU LOG =====");
                assert_eq!(exit_status, 0, "Test exited with wrong status.");
            }
            // else: We're good
        }
        Err(e) => {
            panic!("Qemu testing failed: {}", e);
        }
        _ => {
            panic!("Something weird happened to the Qemu process, please investigate.");
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
    let mut cloned_args = args.clone();
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
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-exit"))?;
        p.exp_string("Started")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
}

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn pfault() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-pfault"))?;
        p.exp_string("[IRQ] Page Fault")?;
        p.exp_regex("Backtrace:")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 6)
    );
}

/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
#[test]
fn gpfault() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-gpfault"))?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #2  - 0x[0-9a-fA-F]+ - bespin::xmain")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 5)
    );
}

/// Make sure we can do kernel memory allocations.
///
/// This smoke tests the physical memory allocator
/// and the global allocator integration.
#[test]
fn alloc() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-alloc"))?;
        p.exp_string("small allocations work.")?;
        p.exp_string("large allocations work.")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
}

/// Test that makes use of SSE in kernel-space and see if it works.AsMut
///
/// Tests that we have correctly set-up the hardware to deal with floating
/// point.
#[test]
fn sse() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-sse"))?;
        p.exp_string("division = 4.566210045662101")?;
        p.exp_string("division by zero = inf")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
}

/// Tests the scheduler (in kernel-space).
#[test]
fn scheduler() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-scheduler"))?;
        p.exp_string("lwt2 ThreadId(1)")?;
        p.exp_string("lwt1 ThreadId(0)")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
}

/// Test that we can initialize the ACPI subsystem (in kernel-space).
#[test]
fn acpi_smoke() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-acpi").cores(80).nodes(8))
            .expect("Can't spawn QEMU instance");

        p.exp_string("ACPI Initialized")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output)
}

/// Test that we can boot additional cores.
//#[test]
fn coreboot() {
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-coreboot").cores(2))?;
        p.exp_string("ACPI Initialized")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
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
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-userspace").user_features(&[
            "test-print",
            "test-map",
            "test-alloc",
            "test-upcall",
            "test-scheduler",
        ]))?;

        p.exp_string("print_test OK")?;
        p.exp_string("upcall_test OK")?;
        p.exp_string("map_test OK")?;
        p.exp_string("alloc_test OK")?;
        p.exp_string("scheduler_test OK")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
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
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p =
            spawn_bespin(&RunnerArgs::new("test-userspace").user_feature("test-rump-tmpfs"))?;
        p.exp_string("bytes_written: 12")?;
        p.exp_string("bytes_read: 12")?;
        output = p.exp_eof()?;
        p.process.exit()
    };

    check_for_successful_exit(qemu_run(), output);
}
