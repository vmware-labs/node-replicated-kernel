extern crate rexpect;
#[macro_use]
extern crate matches;

use std::process;

use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::spawn;

fn spawn_qemu(test: &str) -> Result<rexpect::session::PtySession> {
    let features = format!("integration-tests,{}", test);

    process::Command::new("bash")
        .args(&[
            "run.sh",
            "--features",
            features.as_str(),
            "--log info",
            "--norun",
        ])
        .output()
        .expect("failed to build");

    spawn(
        format!("bash run.sh --features {} --log info", features).as_str(),
        Some(15000),
    )
}

#[test]
fn exit() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-exit")?;
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
fn pfault() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-pfault")?;
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
fn gpfault() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-gpfault")?;
        p.exp_string("[IRQ] GENERAL PROTECTION FAULT")?;
        p.exp_regex("frame #2  - 0x[0-9a-fA-F]+ - bespin::main")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 5)
    );
}

#[test]
fn alloc() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-alloc")?;
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
fn sse() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-sse")?;
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
fn rump_fs() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-rump-tmpfs")?;
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
fn rump_net() {
    fn spawn_dhcpd() -> Result<rexpect::session::PtySession> {
        // XXX: apparmor prevents reading of ./tests/dhcpd.conf for dhcpd on Ubuntu :/
        process::Command::new("service")
            .args(&["apparmor", "teardown"])
            .output()
            .expect("failed to disable apparmor");

        process::Command::new("killall")
            .args(&["dhcpd"])
            .output()
            .expect("failed to disable apparmor");

        spawn("sudo dhcpd -f -d tap0 -cf ./tests/dhcpd.conf", Some(15000))
    }

    fn spawn_receiver() -> Result<rexpect::session::PtySession> {
        spawn("socat UDP-LISTEN:8889,fork stdout", Some(15000))
    }

    fn spawn_ping() -> Result<rexpect::session::PtySession> {
        spawn("ping 172.31.0.10", Some(15000))
    }

    let qemu_run = || -> Result<WaitStatus> {
        let mut dhcp_server = spawn_dhcpd()?;
        let mut receiver = spawn_receiver()?;

        let mut p = spawn_qemu("test-rump-net")?;

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
        dhcp_server.process.kill(SIGTERM)?;
        receiver.process.kill(SIGTERM)?;
        p.process.kill(SIGTERM)
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Signaled(_, SIGTERM, _)
    );
}

#[test]
fn scheduler() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-scheduler")?;
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
fn acpi_smoke() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-acpi")?;
        p.exp_string("acpi initialized")?;
        p.exp_string("madt table processed")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}
