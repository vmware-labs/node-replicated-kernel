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
) -> Result<()>;

pub struct RackscaleRunState {
    pub controller_timeout: u64,
    pub controller_memory: usize,
    pub controller_match_function: RackscaleMatchFunction,
    pub client_timeout: u64,
    pub client_memory: usize,
    pub client_match_function: RackscaleMatchFunction,
    pub kernel_test: String,
    pub built: Built<'static>,
    pub num_clients: usize,
    pub cores_per_client: usize,
    pub shmem_size: usize,
    pub use_affinity: bool,
    pub wait_for_client: bool,
    pub transport: RackscaleTransport,
}

impl RackscaleRunState {
    pub fn new(kernel_test: String, built: Built<'static>) -> RackscaleRunState {
        fn blank_match_function(
            _proc: &mut PtySession,
            _output: &mut String,
            _cores_per_client: usize,
            _num_clients: usize,
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
        }
    }
}

pub fn rackscale_runner<'a>(run: RackscaleRunState) {
    // Do not allow over provisioning
    let machine = Machine::determine();
    assert!(run.cores_per_client * run.num_clients + 1 <= machine.max_cores());

    // Set up network, start DCM, and then create shmem servers
    setup_network(run.num_clients + 1);
    let mut dcm = spawn_dcm(1).expect("Failed to start DCM");
    let mut shmem_files = Vec::new();
    let mut shmem_sockets = Vec::new();
    let mut shmem_servers = Vec::new();
    for i in 0..(run.num_clients + 1) {
        let shmem_affinity = if run.use_affinity {
            Some(i % machine.max_numa_nodes())
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
    let controller = std::thread::Builder::new()
        .name("Controller".to_string())
        .spawn(move || {
            let cmdline_controller =
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

            let mut output = String::new();
            let mut qemu_run = || -> Result<WaitStatus> {
                let mut p = spawn_nrk(&cmdline_controller)?;

                // User-supplied function to check output
                (run.controller_match_function)(
                    &mut p,
                    &mut output,
                    run.cores_per_client,
                    run.num_clients,
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
        let client = std::thread::Builder::new()
            .name(format!("Client{}", i + 1))
            .spawn(move || {
                sleep(Duration::from_millis(CLIENT_BUILD_DELAY * (i as u64 + 1)));
                let cmdline_client = RunnerArgs::new_with_build(&client_kernel_test, &client_build)
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
                    .use_vmxnet3();

                let mut output = String::new();
                let mut qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_client)?;

                    // User-supplied function to check output
                    (run.client_match_function)(
                        &mut p,
                        &mut output,
                        run.cores_per_client,
                        run.num_clients,
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
