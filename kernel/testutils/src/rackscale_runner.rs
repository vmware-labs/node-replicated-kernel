use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{mpsc::channel, Arc, Mutex};
use std::time::Duration;
use std::{thread, thread::sleep};

use rexpect::errors::*;
use rexpect::process::signal::{SIGKILL, SIGTERM};
use rexpect::process::wait::WaitStatus;
use rexpect::session::PtySession;

use crate::builder::{Built, Machine};
use crate::helpers::{
    get_shmem_names, setup_network, spawn_dcm, spawn_nrk, spawn_shmem_server, CLIENT_BUILD_DELAY,
    SHMEM_SIZE,
};
use crate::runner_args::{
    log_qemu_out_with_name, wait_for_sigterm_or_successful_exit_no_log, RackscaleMode,
    RackscaleTransport, RunnerArgs,
};

// TODO: change visibility?
pub fn wait_for_termination<T>(rx: &Receiver<()>) -> bool {
    loop {
        thread::sleep(Duration::from_millis(250));
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => {
                println!("Terminating.");
                break;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
    true
}

// TODO: change visibility?
pub fn notify_of_termination(tx: &Sender<()>) {
    let _ = tx.send(());
}

/// RPC Client registration function
pub type RackscaleMatchFunction = fn(
    proc: &mut PtySession,
    output: &mut String,
    cores_per_client: usize,
    num_clients: usize,
    file_name: &str,
) -> Result<()>;

pub struct RackscaleRunState {
    /// Timeout for the controller process
    pub controller_timeout: u64,
    /// Amount of non-shmem QEMU memory given to the controller
    pub controller_memory: usize,
    /// Function that is called after the controller is spawned to match output of the controller process
    pub controller_match_function: RackscaleMatchFunction,
    /// Timeout for each client process
    pub client_timeout: u64,
    /// Amount of non-shmem QEMU memory given to each client
    pub client_memory: usize,
    /// Function that is called after each client is spawned to match output of the client process
    pub client_match_function: RackscaleMatchFunction,
    /// Kernel test string
    pub kernel_test: String,
    /// Used for generating the command of both the clients and the controller
    pub built: Built<'static>,
    /// Number of client machines to spawn
    pub num_clients: usize,
    /// Number of QEMU cores given to each client
    pub cores_per_client: usize,
    /// Size fo the shmem for each shmem server (1 for controller, and 1 per client)
    pub shmem_size: usize,
    /// Use affinity shmem and cores, that is, try to colocate resources of each qemu instance on a NUMA node
    pub use_affinity: bool,
    /// Wait to close the controller until after the clients signal they are done. Default: false, the clients wait for the controller
    pub wait_for_client: bool,
    /// The RPC transport to use (shmem or ethernet)
    pub transport: RackscaleTransport,
    /// Whether to setup network interfaces/bridges or not. Default is true
    pub setup_network: bool,
    /// The file name, sometimes used to write output to in match functions
    pub file_name: String,
    /// The commandline to use on the clients
    pub cmd: String,
}

impl RackscaleRunState {
    pub fn new(kernel_test: String, built: Built<'static>) -> RackscaleRunState {
        fn blank_match_function(
            _proc: &mut PtySession,
            _output: &mut String,
            _cores_per_client: usize,
            _num_clients: usize,
            _file_name: &str,
        ) -> Result<()> {
            // Do nothing
            Ok(())
        }

        RackscaleRunState {
            controller_timeout: 60_000,
            controller_memory: 1024,
            controller_match_function: blank_match_function,
            client_timeout: 60_000,
            client_memory: 1024,
            client_match_function: blank_match_function,
            kernel_test,
            built,
            num_clients: 1,
            cores_per_client: 1,
            shmem_size: SHMEM_SIZE,
            use_affinity: false,
            wait_for_client: false,
            transport: RackscaleTransport::Shmem,
            setup_network: true,
            file_name: "".to_string(),
            cmd: "".to_string(),
        }
    }
}

pub fn rackscale_runner<'a>(run: RackscaleRunState) {
    // Do not allow over provisioning
    let machine = Machine::determine();
    assert!(run.cores_per_client * run.num_clients + 1 <= machine.max_cores());

    // This is really only necessary is is_affinity is set, but does no harm to calculate always
    let mut vm_cores = vec![run.cores_per_client; run.num_clients + 1];
    vm_cores[0] = 1; // controller vm only has 1 core
    let placement_cores = machine.rackscale_core_affinity(vm_cores);

    // Set up network, start DCM, and then create shmem servers
    if run.setup_network {
        setup_network(run.num_clients + 1);
    }

    // Start DCM
    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");

    // Start shmem servers
    let mut shmem_files = Vec::new();
    let mut shmem_sockets = Vec::new();
    let mut shmem_servers = Vec::new();
    for i in 0..(run.num_clients + 1) {
        let shmem_affinity = if run.use_affinity {
            Some(placement_cores[i].0)
        } else {
            None
        };
        let (shmem_socket, shmem_file) = get_shmem_names(Some(i), run.use_affinity);
        let shmem_server =
            spawn_shmem_server(&shmem_socket, &shmem_file, run.shmem_size, shmem_affinity)
                .expect("Failed to start shmem server 0");
        shmem_files.push(shmem_file);
        shmem_sockets.push(shmem_socket);
        shmem_servers.push(shmem_server);
    }

    let all_outputs = Arc::new(Mutex::new(Vec::new()));

    let (tx, rx) = channel();
    let rx_mut = Arc::new(Mutex::new(rx));
    let tx_mut = Arc::new(Mutex::new(tx));
    let built = Arc::new(run.built);

    // Run controller in separate thread
    let controller_output_array = all_outputs.clone();
    let controller_build = built.clone();
    let controller_shmem_sockets = shmem_sockets.clone();
    let controller_kernel_test = run.kernel_test.clone();
    let controller_rx = rx_mut.clone();
    let controller_tx = tx_mut.clone();
    let controller_file_name = run.file_name.clone();
    let controller_placement_cores = placement_cores.clone();
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let mut cmdline_controller =
                RunnerArgs::new_with_build(&controller_kernel_test, &controller_build)
                    .timeout(run.controller_timeout)
                    .transport(run.transport)
                    .mode(RackscaleMode::Controller)
                    .shmem_size(vec![run.shmem_size as usize; run.num_clients + 1])
                    .shmem_path(controller_shmem_sockets)
                    .tap("tap0")
                    .no_network_setup()
                    .workers(run.num_clients + 1)
                    .use_vmxnet3()
                    .memory(run.controller_memory);

            if run.use_affinity {
                cmdline_controller = cmdline_controller
                    .nodes(1)
                    .node_offset(controller_placement_cores[0].0)
                    .setaffinity(controller_placement_cores[0].1.clone())
            }

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                // User-supplied function to check output
                (run.controller_match_function)(
                    &mut p,
                    &mut output,
                    run.cores_per_client,
                    run.num_clients,
                    &controller_file_name,
                )?;

                for _ in 0..run.num_clients {
                    if run.wait_for_client {
                        // Wait for signal from each client that it is done
                        let rx = controller_rx.lock().expect("Failed to get rx lock");
                        let _ = wait_for_termination::<()>(&rx);
                    } else {
                        // Notify each client it's okay to shutdown
                        let tx = controller_tx.lock().expect("Failed to get tx lock");
                        notify_of_termination(&tx);
                    }
                }

                let ret = p.process.kill(SIGTERM)?;
                output += p.exp_eof()?.as_str();
                Ok(ret)
            };
            let ret = qemu_run();
            controller_output_array
                .lock()
                .expect("Failed to get mutex to output array")
                .push((String::from("Controller"), output));

            // This will only find sigterm, that's okay
            wait_for_sigterm_or_successful_exit_no_log(
                &cmdline_controller,
                ret,
                String::from("Controller"),
            );
        })
        .expect("Controller thread failed to spawn");

    // Run client in separate thead. Wait a bit to make sure controller started
    let mut client_procs = Vec::new();
    for i in 0..run.num_clients {
        let client_output_array: Arc<Mutex<Vec<(String, String)>>> = all_outputs.clone();
        let client_build = built.clone();
        let client_shmem_sockets = shmem_sockets.clone();
        let client_rx = rx_mut.clone();
        let client_tx = tx_mut.clone();
        let client_kernel_test = run.kernel_test.clone();
        let client_file_name = run.file_name.clone();
        let client_cmd = run.cmd.clone();
        let client_placement_cores = placement_cores.clone();
        let client = std::thread::Builder::new()
            .name(format!("Client{}", i + 1))
            .spawn(move || {
                sleep(Duration::from_millis(CLIENT_BUILD_DELAY * (i as u64 + 1)));
                let mut cmdline_client =
                    RunnerArgs::new_with_build(&client_kernel_test, &client_build)
                        .timeout(run.client_timeout)
                        .transport(run.transport)
                        .mode(RackscaleMode::Client)
                        .shmem_size(vec![run.shmem_size as usize; run.num_clients + 1])
                        .shmem_path(client_shmem_sockets)
                        .tap(&format!("tap{}", (i + 1) * 2))
                        .no_network_setup()
                        .workers(run.num_clients + 1)
                        .cores(run.cores_per_client)
                        .memory(run.client_memory)
                        .nobuild() // Use single build for all for consistency
                        .use_vmxnet3()
                        .cmd(&client_cmd);

                if run.use_affinity {
                    cmdline_client = cmdline_client
                        .nodes(1)
                        .node_offset(client_placement_cores[i + 1].0)
                        .setaffinity(client_placement_cores[i + 1].1.clone())
                }

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;

                    // User-supplied function to check output
                    (run.client_match_function)(
                        &mut p,
                        &mut output,
                        run.cores_per_client,
                        run.num_clients,
                        &client_file_name,
                    )?;

                    // Wait for controller to terminate
                    if run.wait_for_client {
                        let tx = client_tx.lock().expect("Failed to get rx lock");
                        notify_of_termination(&tx);
                    } else {
                        let rx = client_rx.lock().expect("Failed to get rx lock");
                        let _ = wait_for_termination::<()>(&rx);
                    }

                    let ret = p.process.kill(SIGTERM);
                    output += p.exp_eof()?.as_str();
                    ret
                };
                // Could exit with 'success' or from sigterm, depending on number of clients.
                let ret = qemu_run();
                client_output_array
                    .lock()
                    .expect("Failed to get mutex to output array")
                    .push((format!("Client{}", i + 1), output));
                wait_for_sigterm_or_successful_exit_no_log(
                    &cmdline_client,
                    ret,
                    format!("Client{}", i + 1),
                );
            })
            .expect("Client thread failed to spawn");
        client_procs.push(client);
    }

    let mut client_rets = Vec::new();
    for client in client_procs {
        client_rets.push(client.join());
    }
    let controller_ret = controller.join();

    for server in shmem_servers.iter_mut() {
        let _ignore = server.send_control('c');
    }
    let _ignore = dcm.process.kill(SIGKILL);

    // If there's been an error, print everything
    if controller_ret.is_err() || (&client_rets).into_iter().any(|ret| ret.is_err()) {
        let outputs = all_outputs.lock().expect("Failed to get output lock");
        for (name, output) in outputs.iter() {
            log_qemu_out_with_name(None, name.to_string(), output.to_string());
        }
        if controller_ret.is_err() {
            let dcm_log = dcm.exp_eof();
            if dcm_log.is_ok() {
                log_qemu_out_with_name(None, "DCM".to_string(), dcm_log.unwrap());
            } else {
                eprintln!("Failed to print DCM log.");
            }
        }
    }

    for client_ret in client_rets {
        client_ret.unwrap();
    }
    controller_ret.unwrap();
}
