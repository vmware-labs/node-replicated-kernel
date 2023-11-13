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
pub const DHCP_ACK_MATCH_NRK2: &'static str = "DHCPACK on 172.31.0.11 to 56:b4:44:e9:62:d1 via br0";

/// Default shmem region size (in MB)
pub const SHMEM_SIZE: usize = 1024;
/// Created by `hugeadm --create-global-mounts`
const SHMEM_AFFINITY_PATH: &'static str = "/var/lib/hugetlbfs/global/pagesize-2MB";

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

pub fn get_shmem_names(id: Option<usize>, is_affinity: bool) -> (String, String) {
    let shmem_id = if let Some(myid) = id {
        myid.to_string()
    } else {
        "".to_string()
    };

    let shmem_file = if is_affinity {
        format!("{}/ivshmem-file{}", SHMEM_AFFINITY_PATH, shmem_id)
    } else {
        format!("ivshmem-file{}", shmem_id)
    };
    (format!("ivshmem-socket{}", shmem_id), shmem_file)
}

/// Spawns a qemu shmem server.
///
/// The server must run before any nrk instance runs.
/// File len is in MB - if using huge pages, should be multiple of huge page size (normally 2 MB)
pub fn spawn_shmem_server(
    socketname: &str,
    filename: &str,
    filelen: usize,
    affinity: Option<usize>,
) -> Result<rexpect::session::PtySession> {
    // Delete any straggler files
    let _ignore = remove_file(socketname);
    let _ignore = remove_file(filename);

    let affinity_str = if let Some(node_affinity) = affinity {
        format!("-a {} -m {}", node_affinity, filename)
    } else {
        format!("-M {}", filename)
    };

    // Run the ivshmem server; not sure how long we'll need it for so we let it run forever.
    let cmd = format!(
        "ivshmem-server -F -S {} -l {}M -n {} {}",
        socketname,
        filelen,
        2, // number of vectors
        affinity_str,
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

#[derive(Debug, Clone, Copy)]
pub enum DCMSolver {
    DCMloc,
    DCMcap,
    Random,
    RoundRobin,
    FillCurrent,
}

impl std::fmt::Display for DCMSolver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DCMSolver::DCMloc => write!(f, "DCMloc"),
            DCMSolver::DCMcap => write!(f, "DCMcap"),
            DCMSolver::Random => write!(f, "R"),
            DCMSolver::RoundRobin => write!(f, "RR"),
            DCMSolver::FillCurrent => write!(f, "FC"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DCMConfig {
    pub solver: DCMSolver,
    pub verbose: bool,     // for info on solve time, allocation placement
    pub dcm_logging: bool, // for debugging
    pub requests_per_solve: usize,
    pub poll_interval: usize,
}
impl DCMConfig {
    fn get_cmd(self) -> String {
        let mut dcm_args = Vec::new();
        dcm_args.push("-r".to_string());
        dcm_args.push(format!("{}", self.requests_per_solve));

        // Set a short poll interval
        dcm_args.push("-p".to_string());
        dcm_args.push(format!("{}", self.poll_interval));

        if self.verbose {
            dcm_args.push("-v".to_string());
        }
        if self.dcm_logging {
            dcm_args.push("-l".to_string());
        }

        dcm_args.push("-s".to_string());
        dcm_args.push(format!("{}", self.solver));

        // Start DCM
        let cmd = format!(
            "java -jar ../target/dcm-scheduler.jar {}",
            dcm_args.join(" "),
        );

        cmd
    }
}

impl Default for DCMConfig {
    fn default() -> Self {
        DCMConfig {
            solver: DCMSolver::DCMloc,
            verbose: false,
            dcm_logging: false,
            requests_per_solve: 1,
            poll_interval: 3,
        }
    }
}

/// Spawns a DCM solver
///
/// Uses target/dcm-scheduler.jar that is set up by run.py
/// -r => number of requests per solve
/// -p => poll interval
pub fn spawn_dcm(cfg: Option<DCMConfig>) -> Result<rexpect::session::PtySession> {
    let cmd = if let Some(cfg) = cfg {
        cfg.get_cmd()
    } else {
        DCMConfig::default().get_cmd()
    };

    eprintln!("Invoke DCM: {}", cmd);
    let ret = spawn(&cmd, None);
    match ret {
        Ok(mut pty) => {
            // Wait only half a second, because sometimes DCM takes a while to kill.
            pty.process.set_kill_timeout(Some(500));
            Ok(pty)
        }
        e => e,
    }
}

/// Spawns a DHCP server on our host using most common interface: tap0
pub fn spawn_dhcpd() -> Result<rexpect::session::PtyReplSession> {
    spawn_dhcpd_with_interface("tap0".to_string())
}

/// Spawns a DHCP server on our host
///
/// It uses our dhcpd config and listens on the tap0 interface
/// (that we set up in our run.py script).
pub fn spawn_dhcpd_with_interface(interface: String) -> Result<rexpect::session::PtyReplSession> {
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
    let cmd = format!(
        "sudo dhcpd -f -d {} --no-pid -cf ./tests/dhcpd.conf",
        interface
    );
    eprintln!("Invoke dhcpd: {}", cmd);
    b.send_line(&cmd)?;
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
