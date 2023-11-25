use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{mpsc::channel, Arc, Mutex};
use std::thread;
use std::time::Duration;

use rexpect::errors::*;
use rexpect::process::signal::{SIGKILL, SIGTERM};
use rexpect::process::wait::WaitStatus;
use rexpect::session::PtySession;

use crate::builder::{Built, Machine};
use crate::helpers::{
    get_shmem_names, setup_network, spawn_dcm, spawn_dhcpd, spawn_nrk, spawn_shmem_server,
    DCMConfig, SHMEM_SIZE,
};
use crate::runner_args::{
    log_qemu_out_with_name, wait_for_sigterm_or_successful_exit,
    wait_for_sigterm_or_successful_exit_no_log, RackscaleMode, RackscaleTransport, RunnerArgs,
};

fn wait_for_signal<T>(rx: &Receiver<()>) -> bool {
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

fn send_signal(tx: &Sender<()>) {
    let _ = tx.send(());
}

/// RPC Client registration function
type RackscaleMatchFn<T> = fn(
    proc: &mut PtySession,
    output: &mut String,
    cores_per_client: usize,
    num_clients: usize,
    file_name: &str,
    is_baseline: bool,
    arg: Option<T>,
) -> Result<()>;

#[derive(Clone)]
pub struct RackscaleRun<T>
where
    T: Clone + Send + 'static,
{
    /// Kernel test string
    kernel_test: String,
    /// Used for generating the command of both the clients and the controller
    built: Built<'static>,
    /// Timeout for the controller process
    pub controller_timeout: u64,
    /// Function that is called after the controller is spawned to match output of the controller process
    pub controller_match_fn: RackscaleMatchFn<T>,
    /// Timeout for each client process
    pub client_timeout: u64,
    /// Amount of non-shmem QEMU memory given to each QEMU instance
    pub memory: usize,
    /// Function that is called after each client is spawned to match output of the client process
    pub client_match_fn: RackscaleMatchFn<T>,
    /// Number of client machines to spawn
    pub num_clients: usize,
    /// Number of QEMU cores given to each client
    pub cores_per_client: usize,
    /// Size fo the shmem for each shmem server (1 for controller, and 1 per client)
    pub shmem_size: usize,
    /// Use affinity shmem (required huge pages enabled and configured on host)
    pub use_affinity_shmem: bool,
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
    /// Argument passed to a matching function
    pub arg: Option<T>,
    /// Run DHCPD in baseline test
    pub run_dhcpd_for_baseline: bool,
    /// Huge huge pages for qemu memory. This requires pre-alloc'ing them on the host before running.
    pub use_qemu_huge_pages: bool,
    /// DCM config
    pub dcm_config: Option<DCMConfig>,
}

impl<T: Clone + Send + 'static> RackscaleRun<T> {
    pub fn new(kernel_test: String, built: Built<'static>) -> RackscaleRun<T> {
        fn blank_match_fn<T>(
            _proc: &mut PtySession,
            _output: &mut String,
            _cores_per_client: usize,
            _num_clients: usize,
            _file_name: &str,
            _is_baseline: bool,
            _arg: Option<T>,
        ) -> Result<()> {
            // Do nothing
            Ok(())
        }

        RackscaleRun {
            controller_timeout: 60_000,
            controller_match_fn: blank_match_fn,
            client_timeout: 60_000,
            client_match_fn: blank_match_fn,
            memory: 1024,
            kernel_test,
            built,
            num_clients: 1,
            cores_per_client: 1,
            shmem_size: SHMEM_SIZE,
            use_affinity_shmem: false,
            wait_for_client: false,
            transport: RackscaleTransport::Shmem,
            setup_network: true,
            file_name: "".to_string(),
            cmd: "".to_string(),
            arg: None,
            run_dhcpd_for_baseline: false,
            use_qemu_huge_pages: false,
            dcm_config: None,
        }
    }

    pub fn run_rackscale(&self) {
        // Do not allow over provisioning
        let machine = Machine::determine();
        assert!(self.cores_per_client * self.num_clients + 1 <= machine.max_cores());
        let controller_cores = self.num_clients + 1;

        let mut vm_cores = vec![self.cores_per_client; self.num_clients + 1];
        vm_cores[0] = controller_cores;
        let placement_cores = machine.rackscale_core_affinity(vm_cores);

        // Set up network
        if self.setup_network {
            setup_network(self.num_clients + 1);
        }

        // Start DCM
        let mut dcm = spawn_dcm(self.dcm_config).expect("Failed to start DCM");

        // Start shmem servers
        let mut shmem_files = Vec::new();
        let mut shmem_sockets = Vec::new();
        let mut shmem_servers = Vec::new();
        for i in 0..(self.num_clients + 1) {
            let shmem_affinity = if self.use_affinity_shmem {
                Some(placement_cores[i].0)
            } else {
                None
            };
            let (shmem_socket, shmem_file) = get_shmem_names(Some(i), self.use_affinity_shmem);
            let shmem_server =
                spawn_shmem_server(&shmem_socket, &shmem_file, self.shmem_size, shmem_affinity)
                    .expect("Failed to start shmem server 0");
            shmem_files.push(shmem_file);
            shmem_sockets.push(shmem_socket);
            shmem_servers.push(shmem_server);
        }

        let all_outputs = Arc::new(Mutex::new(Vec::new()));

        let (tx, rx) = channel();
        let rx_mut = Arc::new(Mutex::new(rx));
        let tx_mut = Arc::new(Mutex::new(tx));

        let (tx_build_timer, rx_build_timer) = channel();
        let tx_build_timer_mut = Arc::new(Mutex::new(tx_build_timer));

        // Run controller in separate thread
        let controller_output_array: Arc<Mutex<Vec<(String, String)>>> = all_outputs.clone();
        let controller_shmem_sockets = shmem_sockets.clone();
        let controller_kernel_test = self.kernel_test.clone();
        let controller_rx = rx_mut.clone();
        let controller_tx = tx_mut.clone();
        let controller_file_name = self.file_name.clone();
        let controller_placement_cores = placement_cores.clone();
        let state = self.clone();
        let controller_tx_build_timer = tx_build_timer_mut.clone();
        let use_large_pages = self.use_qemu_huge_pages;
        let controller = std::thread::Builder::new()
            .name("Controller".to_string())
            .spawn(move || {
                let mut cmdline_controller =
                    RunnerArgs::new_with_build(&controller_kernel_test, &state.built)
                        .timeout(state.controller_timeout)
                        .transport(state.transport)
                        .mode(RackscaleMode::Controller)
                        .shmem_size(vec![state.shmem_size as usize; state.num_clients + 1])
                        .shmem_path(controller_shmem_sockets)
                        .tap("tap0")
                        .no_network_setup()
                        .workers(state.num_clients + 1)
                        .use_vmxnet3()
                        .memory(state.memory)
                        .nodes(1)
                        .cores(controller_cores)
                        .node_offset(controller_placement_cores[0].0)
                        .setaffinity(controller_placement_cores[0].1.clone());

                if use_large_pages {
                    cmdline_controller = cmdline_controller.large_pages().prealloc();
                }

                let mut output = String::new();
                let qemu_run = || -> Result<WaitStatus> {
                    let mut p = spawn_nrk(&cmdline_controller)?;

                    output += p.exp_string("CONTROLLER READY")?.as_str();
                    {
                        let tx = controller_tx_build_timer
                            .lock()
                            .expect("Failed to get build timer lock");
                        send_signal(&tx);
                    }

                    // User-supplied function to check output
                    (state.controller_match_fn)(
                        &mut p,
                        &mut output,
                        state.cores_per_client,
                        state.num_clients,
                        &controller_file_name,
                        false,
                        state.arg,
                    )?;

                    for _ in 0..state.num_clients {
                        if state.wait_for_client {
                            // Wait for signal from each client that it is done
                            let rx = controller_rx.lock().expect("Failed to get rx lock");
                            let _ = wait_for_signal::<()>(&rx);
                        }
                    }

                    let ret = p.process.kill(SIGTERM)?;
                    output += p.exp_eof()?.as_str();
                    Ok(ret)
                };
                let ret = qemu_run();

                if ret.is_err() {
                    let tx = controller_tx_build_timer
                        .lock()
                        .expect("Failed to get build timer lock");
                    send_signal(&tx);
                }

                if !state.wait_for_client {
                    let tx = controller_tx.lock().expect("Failed to get tx lock");
                    for _ in 0..state.num_clients {
                        // Notify each client it's okay to shutdown
                        send_signal(&tx);
                    }
                }

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
        for i in 0..self.num_clients {
            wait_for_signal::<()>(&rx_build_timer);

            let client_output_array: Arc<Mutex<Vec<(String, String)>>> = all_outputs.clone();
            let client_shmem_sockets = shmem_sockets.clone();
            let client_rx = rx_mut.clone();
            let client_tx = tx_mut.clone();
            let client_kernel_test = self.kernel_test.clone();
            let client_file_name = self.file_name.clone();
            let client_cmd = self.cmd.clone();
            let client_placement_cores = placement_cores.clone();
            let state = self.clone();
            let client_tx_build_timer = tx_build_timer_mut.clone();
            let use_large_pages = self.use_qemu_huge_pages;
            let client = std::thread::Builder::new()
                .name(format!("Client{}", i + 1))
                .spawn(move || {
                    let mut cmdline_client =
                        RunnerArgs::new_with_build(&client_kernel_test, &state.built)
                            .timeout(state.client_timeout)
                            .transport(state.transport)
                            .mode(RackscaleMode::Client)
                            .shmem_size(vec![state.shmem_size as usize; state.num_clients + 1])
                            .shmem_path(client_shmem_sockets)
                            .tap(&format!("tap{}", (i + 1) * 2))
                            .no_network_setup()
                            .workers(state.num_clients + 1)
                            .cores(state.cores_per_client)
                            .memory(state.memory)
                            .nobuild() // Use single build for all for consistency
                            .use_vmxnet3()
                            .cmd(&client_cmd)
                            .nodes(1)
                            .node_offset(client_placement_cores[i + 1].0)
                            .setaffinity(client_placement_cores[i + 1].1.clone());

                    if use_large_pages {
                        cmdline_client = cmdline_client.large_pages().prealloc();
                    }

                    let mut output = String::new();
                    let qemu_run = || -> Result<WaitStatus> {
                        let mut p = spawn_nrk(&cmdline_client)?;

                        output += p.exp_string("CLIENT READY")?.as_str();
                        {
                            let tx = client_tx_build_timer
                                .lock()
                                .expect("Failed to get build timer lock");
                            send_signal(&tx);
                        }

                        // User-supplied function to check output
                        (state.client_match_fn)(
                            &mut p,
                            &mut output,
                            state.cores_per_client,
                            state.num_clients,
                            &client_file_name,
                            false,
                            state.arg,
                        )?;

                        // Wait for controller to terminate
                        if !state.wait_for_client {
                            let rx = client_rx.lock().expect("Failed to get rx lock");
                            let _ = wait_for_signal::<()>(&rx);
                        }

                        let ret = p.process.kill(SIGTERM);
                        output += p.exp_eof()?.as_str();
                        ret
                    };

                    // Could exit with 'success' or from sigterm, depending on number of clients.
                    let ret = qemu_run();

                    if ret.is_err() {
                        let tx = client_tx_build_timer
                            .lock()
                            .expect("Failed to get build timer lock");
                        send_signal(&tx);
                    }

                    if state.wait_for_client {
                        let tx = client_tx.lock().expect("Failed to get rx lock");
                        send_signal(&tx);
                    }

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

    pub fn run_baseline(&self) {
        // Here we assume run.num_clients == run.num_replicas (num nodes)
        // And the controller match function, timeout, memory will be used

        let machine = Machine::determine();
        assert!(self.cores_per_client * self.num_clients + 1 <= machine.max_cores());

        // This is really only necessary is is_affinity is set, but does no harm to calculate always
        let vm_cores = vec![self.cores_per_client; self.num_clients];
        let placement_cores = machine.rackscale_core_affinity(vm_cores);
        let mut all_placement_cores = Vec::new();
        for placement in placement_cores {
            all_placement_cores.extend(placement.1);
        }

        // Set up network
        if self.setup_network {
            setup_network(self.num_clients + 1);
        }

        let mut cmdline_baseline = RunnerArgs::new_with_build(&self.kernel_test, &self.built)
            .timeout(self.controller_timeout)
            .memory(self.memory)
            .workers(1)
            .cores(self.cores_per_client * self.num_clients)
            .cmd(&self.cmd)
            .no_network_setup()
            .nodes(self.num_clients)
            .setaffinity(all_placement_cores);

        if self.use_qemu_huge_pages {
            cmdline_baseline = cmdline_baseline.large_pages().prealloc();
        }

        let mut output = String::new();
        let mut qemu_run = || -> Result<WaitStatus> {
            let dhcpd_server = if self.run_dhcpd_for_baseline {
                Some(spawn_dhcpd()?)
            } else {
                None
            };
            let mut p = spawn_nrk(&cmdline_baseline)?;
            (self.controller_match_fn)(
                &mut p,
                &mut output,
                self.cores_per_client,
                self.num_clients,
                &self.file_name,
                true,
                self.arg.clone(),
            )?;
            if let Some(mut server) = dhcpd_server {
                server.send_control('c')?;
            }
            let ret = p.process.kill(SIGTERM)?;
            output += p.exp_eof()?.as_str();
            Ok(ret)
        };
        wait_for_sigterm_or_successful_exit(&cmdline_baseline, qemu_run(), output);
    }
}

pub struct RackscaleBench<T: Clone + Send + 'static> {
    // Test to run
    pub test: RackscaleRun<T>,
    // Function to calculate the command. Takes as argument number of application cores
    pub cmd_fn: fn(usize, Option<T>) -> String,
    // Function to calculate the timeout. Takes as argument number of application cores
    pub rackscale_timeout_fn: fn(usize) -> u64,
    // Function to calculate the timeout. Takes as argument number of application cores
    pub baseline_timeout_fn: fn(usize) -> u64,
    // Function to calculate memory (excpeting controller memory). Takes as argument number of application cores and is_smoke
    pub mem_fn: fn(usize, bool) -> usize,
}

impl<T: Clone + Send + 'static> RackscaleBench<T> {
    pub fn run_bench(&self, is_baseline: bool, is_smoke: bool) {
        let test_run = &mut self.test.clone();

        // Set rackscale appropriately, rebuild if necessary.
        if !is_baseline != test_run.built.with_args.rackscale {
            eprintln!("\tRebuilding with rackscale={}", !is_baseline,);
            test_run.built = test_run
                .built
                .with_args
                .clone()
                .set_rackscale(!is_baseline)
                .build();
        }

        test_run.setup_network = false;

        // Find max cores, max numa, and max cores per node
        let machine = Machine::determine();
        let max_cores = if is_smoke { 2 } else { machine.max_cores() };
        let max_numa = machine.max_numa_nodes();
        let total_cores_per_node = core::cmp::max(1, max_cores / max_numa);

        // Do initial network configuration
        let mut num_clients = 1; // num_clients == num_replicas, for baseline
        if is_baseline {
            setup_network(1);
        } else {
            setup_network(num_clients + 1);
        }

        let mut total_cores = 1;
        while total_cores < max_cores {
            // Round up to get the number of clients
            let new_num_clients = (total_cores + (total_cores_per_node - 1)) / total_cores_per_node;

            // Do network setup if number of clients has changed.
            if num_clients != new_num_clients {
                num_clients = new_num_clients;
                if !is_baseline {
                    setup_network(num_clients + 1);
                }

                // ensure total cores is divisible by num clients
                total_cores = total_cores - (total_cores % num_clients);
            }
            let cores_per_client = total_cores / num_clients;

            // Break if not enough total cores for the controller, or if we would have to split controller across nodes to make it fit
            // We want controller to have it's own socket, so if it's not a 1 socket machine, break when there's equal number of clients
            // to numa nodes.
            if total_cores + num_clients + 1 > machine.max_cores()
                || num_clients == machine.max_numa_nodes()
                    && cores_per_client + num_clients + 1 > total_cores_per_node
                || num_clients == max_numa && max_numa > 1
            {
                break;
            }

            // Print information about each test we run
            let test_type = if is_baseline {
                "baseline NrOS"
            } else {
                "rackscale"
            };
            eprintln!(
                "\tRunning {} test with {:?} total core(s), {:?} (client|replica)(s) (cores_per_(client|replica)={:?})",
                test_type, total_cores, num_clients, cores_per_client
            );

            // Calculate resources for this tesst
            test_run.cores_per_client = cores_per_client;
            test_run.num_clients = num_clients;

            // Set controller timeout for this test
            test_run.controller_timeout = test_run.client_timeout;

            // Calculate command based on the number of cores
            test_run.cmd = (self.cmd_fn)(total_cores, test_run.arg.clone());

            // Caclulate memory and timeouts, and then run test
            if is_baseline {
                test_run.client_timeout = (self.baseline_timeout_fn)(total_cores);
                // Total client memory in test is: (mem_based_on_cores) + shmem_size * num_clients
                test_run.memory = (self.mem_fn)(total_cores, is_smoke)
                    + test_run.shmem_size * test_run.num_clients;

                test_run.run_baseline();
            } else {
                test_run.client_timeout = (self.rackscale_timeout_fn)(total_cores);
                test_run.memory = (self.mem_fn)(total_cores, is_smoke) / test_run.num_clients;

                test_run.run_rackscale();
            }

            if total_cores == 1 {
                total_cores = 0;
            }

            if num_clients == 3 {
                total_cores += 3;
            } else {
                total_cores += 4;
            }
        }
    }
}
