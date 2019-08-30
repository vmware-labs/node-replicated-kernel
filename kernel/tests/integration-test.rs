#![feature(vec_remove_item)]

extern crate rexpect;
#[macro_use]
extern crate matches;

use std::process;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::{spawn, spawn_bash};

/// Arguments passed to the run.sh script to configure a test.
struct RunnerArgs<'a> {
    /// Test name of kernel integration test.
    kernel_features: Vec<&'a str>,
    /// Features passed to compiled user-space modules.
    user_features: Vec<&'a str>,
    /// Number of NUMA nodes the VM should have.
    nodes: usize,
    /// Number of cores the VM should have.
    cores: usize,
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
            cmd: None,
            mods: Vec::new(),
            release: false,
            norun: false,
        }
    }

    fn kernel_features(&'a mut self, kernel_features: &[&'a str]) -> &'a mut RunnerArgs {
        self.kernel_features.extend_from_slice(kernel_features);
        self
    }

    fn kernel_feature(&'a mut self, kernel_feature: &'a str) -> &'a mut RunnerArgs {
        self.kernel_features.push(kernel_feature);
        self
    }

    fn user_features(&'a mut self, user_features: &[&'a str]) -> &'a mut RunnerArgs {
        self.user_features.extend_from_slice(user_features);
        self
    }

    fn user_feature(&'a mut self, user_feature: &'a str) -> &'a mut RunnerArgs {
        self.user_features.push(user_feature);
        self
    }

    fn nodes(&'a mut self, nodes: usize) -> &'a mut RunnerArgs {
        self.nodes = nodes;
        self
    }

    fn cores(&'a mut self, cores: usize) -> &'a mut RunnerArgs {
        self.cores = cores;
        self
    }

    fn cmd(&'a mut self, cmd: &'a str) -> &'a mut RunnerArgs {
        self.cmd = Some(cmd);
        self
    }

    fn modules(&'a mut self, mods: &[&'a str]) -> &'a mut RunnerArgs {
        self.mods.extend_from_slice(mods);
        self
    }

    fn module(&'a mut self, module: &'a str) -> &'a mut RunnerArgs {
        self.mods.push(module);
        self
    }

    fn release(&'a mut self) -> &'a mut RunnerArgs {
        self.release = true;
        self
    }

    fn norun(&'a mut self) -> &'a mut RunnerArgs {
        self.norun = true;
        self
    }
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
    let kernel_features = format!("integration-test,{}", args.kernel_features.join(","));
    let user_features = args.user_features.join(",");
    let cores = format!("{}", args.cores);
    let nodes = format!("{}", args.nodes);

    let mut cmd = vec![
        "run.sh",
        "--kfeatures",
        kernel_features.as_str(),
        "--cores",
        cores.as_str(),
        "--nodes",
        nodes.as_str(),
        "--cmd",
        "log=info",
        "--norun",
    ];

    match args.user_features.is_empty() {
        false => {
            cmd.push("--ufeatures");
            cmd.push(user_features.as_str());
        }
        true => {}
    };

    let o = process::Command::new("bash")
        .args(&cmd)
        .output()
        .expect("failed to build");
    assert!(
        o.status.success(),
        "Building test failed: {:?}",
        cmd.join(" ")
    );

    // Now run the command, by removing the --norun and adding bash to the front
    let no_run = cmd.remove_item(&"--norun");
    cmd.insert(0, "bash");
    assert!(no_run.is_some(), "Found and removed no_run in cmd");

    spawn(&cmd.join(" "), Some(15000))
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
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-exit"))?;
        p.exp_string("Started")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
#[test]
fn pfault() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-pfault"))?;
        p.exp_string("[IRQ] Page Fault")?;
        p.exp_regex("Backtrace:")?;
        p.exp_eof()?;
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
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-gpfault"))?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #2  - 0x[0-9a-fA-F]+ - bespin::xmain")?;
        p.exp_eof()?;
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
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-alloc"))?;
        p.exp_string("small allocations work.")?;
        p.exp_string("large allocations work.")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

/// Test that makes use of SSE in kernel-space and see if it works.AsMut
///
/// Tests that we have correctly set-up the hardware to deal with floating
/// point.
#[test]
fn sse() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-sse"))?;
        p.exp_string("division = 4.566210045662101")?;
        p.exp_string("division by zero = inf")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

/// Tests the scheduler (in kernel-space).
#[test]
fn scheduler() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-scheduler"))?;
        p.exp_string("lwt2 ThreadId(1)")?;
        p.exp_string("lwt1 ThreadId(0)")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

/// Test that we can initialize the ACPI subsystem (in kernel-space).
#[test]
fn acpi_smoke() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-acpi").cores(2))?;
        p.exp_string("ACPI Initialized")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

/// Test that we can boot additional cores.
#[test]
fn coreboot() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_bespin(&RunnerArgs::new("test-acpi").cores(2))?;
        p.exp_string("ACPI Initialized")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
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
    let qemu_run = || -> Result<WaitStatus> {
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
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
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
    let qemu_run = || -> Result<WaitStatus> {
        let mut p =
            spawn_bespin(&RunnerArgs::new("test-userspace").user_feature("test-rump-tmpfs"))?;
        p.exp_string("bytes_written: 12")?;
        p.exp_string("bytes_read: 12")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}
