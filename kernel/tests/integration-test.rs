extern crate rexpect;
#[macro_use]
extern crate matches;

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;
use rexpect::spawn;

fn spawn_qemu(test: &str) -> Result<rexpect::session::PtySession> {
    spawn(
        format!("bash run.sh --features integration-tests,{}", test).as_str(),
        Some(25000),
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
        p.exp_regex("frame #2  - 0x[0-9a-fA-F]+ - arch_init")?;
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
