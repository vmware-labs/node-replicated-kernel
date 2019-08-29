#![feature(vec_remove_item)]

extern crate rexpect;
#[macro_use]
extern crate matches;

use std::process;

use rexpect::errors::*;
use rexpect::process::signal::{SIGINT, SIGTERM};
use rexpect::process::wait::WaitStatus;
use rexpect::{spawn, spawn_bash};

/// Builds the kernel and spawns a qemu instance of it.
///
/// For kernel-code it gets compiled with kernel features `integration-test`
/// and whatever feature is supplied in `test`. For user-space modules
/// we pass everything in `user_features` to the build.
///
/// It will make sure the code is compiled and ready to launch.
/// Otherwise the 15s timeout we set on the PtySession may not be enough
/// to build from scratch and run the test.
fn spawn_qemu(
    kernel_features: &str,
    user_features: Option<&str>,
) -> Result<rexpect::session::PtySession> {
    let features = format!("integration-test,{}", test);

    let mut cmd = vec![
        "run.sh",
        "--kfeatures",
        kernel_features.as_str(),
        "--cmd",
        "log=info",
        "--norun",
    ];

    match user_features {
        Some(features) => {
            cmd.push("--ufeatures");
            cmd.push(features);
        }
        None => {}
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

#[test]
/// Make sure exiting the kernel works.
///
/// We have a special ioport that we use to signal the exit to
/// qemu and some parsing logic to read the exit code
/// and communicate if our tests passed or failed.
fn exit() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-exit", None)?;
        p.exp_string("Started")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

#[test]
/// Make sure the page-fault handler functions as expected.
/// In essence a trap should be raised and we should get a backtrace.
fn pfault() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-pfault", None)?;
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

#[test]
/// Make sure general protection fault handling works as expected.
///
/// Again we'd expect a trap and a backtrace.
fn gpfault() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-gpfault", None)?;
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

#[test]
/// Make sure we can do kernel memory allocations.
///
/// This smoke tests the physical memory allocator
/// and the global allocator integration.
fn alloc() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-alloc", None)?;
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

#[test]
/// Test that makes use of SSE in kernel-space and see if it works.AsMut
///
/// Tests that we have correctly set-up the hardware to deal with floating
/// point.
fn sse() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-sse", None)?;
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

#[test]
/// Tests the rump FS (in kernel-space).
///
/// Checks that we can initialize a BSD libOS and run FS operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
fn rump_fs() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("rumprt,test-rump-tmpfs", None)?;
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

#[test]
/// Tests the rump network stack (in kernel-space).
///
/// This tests spawns a DHCP server where we request an IP from,
/// tries to ping the network stack in the guest and then receives
/// some packets from the guest.
///
/// Checks that we can initialize a BSD libOS and run network operations.
/// This implicitly tests many components such as the scheduler, memory
/// management, IO and device interrupts.
fn rump_net() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_qemu("rumprt,test-rump-net", None)?;

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

#[test]
/// Tests the scheduler (in kernel-space).
fn scheduler() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-scheduler", None)?;
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

#[test]
/// Test that we can initialize the ACPI subsystem (in kernel-space).
fn acpi_smoke() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-acpi", None)?;
        p.exp_string("ACPI initialized")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

#[test]
/// Tests that basic user-space support is functional.
///
/// This tests various user-space components such as:
///  * process loading
///  * system calls (printing, mem. mgmt.)
///  * user-space scheduling and upcalls
///  * BSD libOS in user-space
///
fn userspace_smoke() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu(
            "test-userspace",
            Some("test-print,test-map,test-alloc,test-upcall,test-scheduler,test-rump-tmpfs"),
        )?;
        p.exp_string("print_test OK")?;
        p.exp_string("upcall_test OK")?;
        p.exp_string("map_test OK")?;
        p.exp_string("alloc_test OK")?;
        p.exp_string("scheduler_test OK")?;
        p.exp_string("test_rump_tmpfs OK")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

#[test]
/// Tests that user-space networking is functional.
///
/// This tests various user-space components such as:
///  * BSD libOS network stack
///  * PCI/user-space drivers
///  * Interrupt registration and upcalls
///
fn userspace_net() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_qemu("test-userspace", Some("test-rump-net"))?;

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
