// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s03_*`: High level kernel functionality: Spawn cores, run user-space programs

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;
use rexpect::spawn;

use testutils::builder::BuildArgs;
use testutils::helpers::{spawn_nrk, spawn_shmem_server, SHMEM_PATH, SHMEM_SIZE};
use testutils::runner_args::{check_for_successful_exit, RunnerArgs};

/// Test that we boot up all cores in the system.
#[cfg(not(feature = "baremetal"))] // TODO: can be ported to baremetal
#[test]
fn s03_coreboot() {
    let build = BuildArgs::default().build();
    let cmdline = &RunnerArgs::new_with_build("coreboot", &build)
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
    let build = BuildArgs::default()
        .user_features(&[
            "test-print",
            "test-map",
            "test-alloc",
            "test-upcall",
            "test-scheduler",
            "test-syscalls",
        ])
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace", &build);
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

/// Tests that the vmxnet3 driver is functional together with the smoltcp
/// network stack.
#[cfg(not(feature = "baremetal"))]
#[test]
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

    let build = BuildArgs::default().build();
    let cmdline = RunnerArgs::new_with_build("vmxnet-smoltcp", &build)
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

/// Tests that basic physical allocation support is functional.
#[test]
fn s03_phys_alloc() {
    let build = BuildArgs::default()
        .module("init")
        .user_feature("test-phys-alloc")
        .release()
        .build();
    let cmdline = RunnerArgs::new_with_build("userspace-smp", &build).timeout(20_000);
    let mut output = String::new();

    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;

        output += p.exp_string("phys_alloc_test OK")?.as_str();
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
}

/// Test that the shared memory device is functional by running NRK twice: once
/// to produce data, and one to consume it.
#[cfg(not(feature = "baremetal"))]
#[test]
fn s03_ivshmem_write_and_read() {
    let build = BuildArgs::default().build();

    let cmdline = RunnerArgs::new_with_build("cxl-write", &build)
        .timeout(30_000)
        .shmem_size(SHMEM_SIZE as usize)
        .shmem_path(SHMEM_PATH);

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);

    let cmdline = RunnerArgs::new_with_build("cxl-read", &build)
        .timeout(30_000)
        .shmem_size(SHMEM_SIZE as usize)
        .shmem_path(SHMEM_PATH);

    let mut output = String::new();
    let mut qemu_run = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&cmdline)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };

    check_for_successful_exit(&cmdline, qemu_run(), output);
    let _ignore = shmem_server.send_control('c');
}

/// Test that the shared memory device with interrupts is functional
#[cfg(not(feature = "baremetal"))]
#[test]
fn s03_ivshmem_interrupt() {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    let build = Arc::new(BuildArgs::default().kernel_feature("test-shmem").build());

    let mut shmem_server =
        spawn_shmem_server(SHMEM_PATH, SHMEM_SIZE).expect("Failed to start shmem server");

    // Start interruptee process
    let build1 = build.clone();
    let interruptee = std::thread::spawn(move || {
        let interruptee_cmdline = RunnerArgs::new_with_build("shmem-interruptee", &build1)
            .cores(2)
            .timeout(90_000)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH);

        let mut interruptee_output = String::new();
        let mut interruptee_qemu_run = || -> Result<WaitStatus> {
            let mut p = spawn_nrk(&interruptee_cmdline)?;
            interruptee_output += p.exp_string("Got a shmem interrupt")?.as_str();
            interruptee_output += p.exp_eof()?.as_str();
            p.process.exit()
        };
        check_for_successful_exit(
            &interruptee_cmdline,
            interruptee_qemu_run(),
            interruptee_output,
        );
    });

    // Start interruptor processs
    let build2 = build.clone();
    let interruptor = std::thread::spawn(move || {
        let interruptor_cmdline = RunnerArgs::new_with_build("shmem-interruptor", &build2)
            .cores(2)
            .timeout(90_000)
            .shmem_size(SHMEM_SIZE as usize)
            .shmem_path(SHMEM_PATH);

        let mut interruptor_output = String::new();
        let mut interruptor_qemu_run = || -> Result<WaitStatus> {
            sleep(Duration::from_millis(10_000));
            let mut p = spawn_nrk(&interruptor_cmdline)?;
            interruptor_output += p.exp_string("Sending shmem interrupt")?.as_str();
            interruptor_output += p.exp_eof()?.as_str();
            p.process.exit()
        };
        check_for_successful_exit(
            &interruptor_cmdline,
            interruptor_qemu_run(),
            interruptor_output,
        );
    });

    interruptee.join().unwrap();
    interruptor.join().unwrap();

    let _ignore = shmem_server.send_control('c');
}
