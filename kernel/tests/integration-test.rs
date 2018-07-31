extern crate rexpect;
#[macro_use]
extern crate matches;

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;
use rexpect::spawn;

fn spawn_qemu(test: &str) -> Result<rexpect::session::PtySession> {
    spawn(
        format!("bash run.sh --features integration-tests,{}", test).as_str(),
        Some(2000),
    )
}

#[test]
fn test_exit() {
    let qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_qemu("test-exit")?;
        p.exp_string("[bespin::arch] Started")?;
        p.exp_eof()?;
        p.process.exit()
    };

    assert_matches!(
        qemu_run().unwrap_or_else(|e| panic!("Qemu testing failed: {}", e)),
        WaitStatus::Exited(_, 0)
    );
}

#[test]
fn test_pfault() {
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
