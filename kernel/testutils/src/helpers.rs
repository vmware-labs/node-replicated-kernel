// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::remove_file;
use std::io::ErrorKind;
use std::process;

use rexpect::errors::*;
use rexpect::process::wait::WaitStatus;
use rexpect::session::spawn_command;
use rexpect::{spawn, spawn_bash};

use crate::builder::BuildArgs;
use crate::runner_args::RunnerArgs;

/// Line we use in dhcpd to match for giving IP to Qemu VM.
///
/// # Depends on
/// - `tests/dhcpd.conf`: config file contains match of MAC to IP
pub const DHCP_ACK_MATCH: &'static str = "DHCPACK on 172.31.0.10 to 56:b4:44:e9:62:d0 via tap0";

/// Shmem related default values
pub const SHMEM_PATH: &str = "ivshmem-file";
pub const SHMEM_SIZE: u64 = 8;

/// Sets up network interfaces and bridge for rackscale mode
///
/// num_nodes includes the controller in the count. Internally this
/// invokes run.py in 'network-only' mode.
pub fn setup_network(num_nodes: usize) {
    // Setup network
    let net_build = BuildArgs::default().build();
    let network_setup = RunnerArgs::new_with_build("network_only", &net_build)
        .workers(num_nodes)
        .network_only();

    let mut output = String::new();
    let mut network_setup = || -> Result<WaitStatus> {
        let mut p = spawn_nrk(&network_setup)?;
        output += p.exp_eof()?.as_str();
        p.process.exit()
    };
    network_setup().unwrap();
}

/// Spawns a qemu shmem server.
///
/// The server must run before any nrk instance runs.
pub fn spawn_shmem_server(filename: &str, filelen: u64) -> Result<rexpect::session::PtySession> {
    // Delete any straggler files
    let _ignore = remove_file(filename);

    // Run the ivshmem server; not sure how long we'll need it for so we let it run forever.
    let cmd = format!(
        "ivshmem-server -F -S {} -l {} -n {} ",
        filename,
        filelen * 1024 * 1024,
        2, // number of vectors
    );
    eprintln!("Invoke shmem server: {}", cmd);
    spawn(&cmd, None)
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
pub fn spawn_nrk(args: &RunnerArgs) -> Result<rexpect::session::PtySession> {
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
    let ret = spawn_command(o, timeout);
    ret
}

/// Spawns a DCM solver
///
/// Uses target/dcm-scheduler.jar that is set up by run.py
/// -r => number of requests per solve
pub fn spawn_dcm(r: usize, timeout: u64) -> Result<rexpect::session::PtyReplSession> {
    // Remove existing DCM log file
    let file_name = "dcm.log";
    let _ignore = remove_file(file_name);

    let mut dcm_args = Vec::new();
    dcm_args.push("-r".to_string());
    dcm_args.push(format!("{}", r));

    // Start DCM
    let cmd = format!(
        "java -jar ../target/dcm-scheduler.jar {} > {}",
        dcm_args.join(" "),
        file_name
    );
    eprintln!("Invoke DCM: {}", cmd);
    let mut b = spawn_bash(Some(timeout))?;
    b.send_line(&cmd)?;
    Ok(b)
}

/// Spawns a DHCP server on our host
///
/// It uses our dhcpd config and listens on the tap0 interface
/// (that we set up in our run.py script).
pub fn spawn_dhcpd() -> Result<rexpect::session::PtyReplSession> {
    // apparmor prevents reading of ./tests/dhcpd.conf for dhcpd
    // on Ubuntu, so we make sure it is disabled:
    let o = process::Command::new("sudo")
        .args(&["aa-teardown"])
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
pub fn spawn_receiver() -> Result<rexpect::session::PtySession> {
    spawn("socat UDP-LISTEN:8889,fork stdout", Some(20_000))
}

/// Helper function that tries to ping the QEMU guest.
pub fn spawn_ping() -> Result<rexpect::session::PtySession> {
    spawn("ping 172.31.0.10", Some(20_000))
}

#[allow(unused)]
pub fn spawn_nc(port: u16) -> Result<rexpect::session::PtySession> {
    spawn(format!("nc 172.31.0.10 {}", port).as_str(), Some(20000))
}
