// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Various integration tests that run inside a VM and test different aspects
// of the kernel. Check `kernel/tests/*.rs` for the host-side
// counterpart.

use crate::arch::debug::shutdown;
use crate::ExitReason;

type MainFn = fn();

#[cfg(feature = "integration-test")]
const INTEGRATION_TESTS: [(&str, MainFn); 29] = [
    ("exit", just_exit_ok),
    ("wrgsbase", wrgsbase),
    ("pfault-early", just_exit_fail),
    ("gpfault-early", just_exit_fail),
    ("pfault", pfault),
    ("gpfault", gpfault),
    ("double-fault", just_exit_fail),
    ("alloc", alloc),
    ("sse", sse),
    ("time", time),
    ("timer", timer),
    ("acpi-smoke", acpi_smoke),
    ("acpi-topology", acpi_topology),
    ("coreboot-smoke", coreboot_smoke),
    ("coreboot-nrlog", coreboot_nrlog),
    ("thread-local", thread_local_usage),
    ("nvdimm-discover", nvdimm_discover),
    ("coreboot", coreboot),
    ("userspace", userspace),
    ("userspace-smp", userspace),
    ("vspace-debug", vspace_debug),
    ("shootdown-simple", shootdown_simple),
    ("replica-advance", replica_advance),
    ("gdb", gdb),
    ("vmxnet-smoltcp", vmxnet_smoltcp),
    ("cxl-read", cxl_read),
    ("cxl-write", cxl_write),
    ("shmem-interruptor", shmem_interruptor),
    ("shmem-interruptee", shmem_interruptee),
];

#[cfg(feature = "integration-test")]
pub(crate) fn run_test(name: &'static str) -> ! {
    for (test, fun) in INTEGRATION_TESTS {
        if name == test {
            fun();
        }
    }
    panic!("Can't find requested test");
}

/// Test timestamps in the kernel.
#[cfg(feature = "integration-test")]
fn time() {
    fn determine_cpu_frequency() -> u64 {
        const MHZ_TO_HZ: u64 = 1000000;
        const KHZ_TO_HZ: u64 = 1000;
        let cpuid = x86::cpuid::CpuId::new();

        // Use info from hypervisor if available:
        if let Some(hv) = cpuid.get_hypervisor_info() {
            if let Some(tsc_khz) = hv.tsc_frequency() {
                return tsc_khz as u64 * KHZ_TO_HZ;
            }
        }

        // Use CpuId info if available:
        if let Some(tinfo) = cpuid.get_tsc_info() {
            if let Some(freq) = tinfo.tsc_frequency() {
                return freq;
            } else if tinfo.numerator() != 0 && tinfo.denominator() != 0 {
                // Approximate with the processor frequency:
                if let Some(pinfo) = cpuid.get_processor_frequency_info() {
                    let cpu_base_freq_hz = pinfo.processor_base_frequency() as u64 * MHZ_TO_HZ;
                    let crystal_hz =
                        cpu_base_freq_hz * tinfo.denominator() as u64 / tinfo.numerator() as u64;
                    return crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64;
                }
            }
        }

        3000 * MHZ_TO_HZ
    }

    use klogger::sprintln;

    unsafe {
        let tsc = x86::time::rdtsc();
        let tsc2 = x86::time::rdtsc();

        let start = rawtime::Instant::now();
        let _done = start.elapsed().as_nanos();
        // We do this twice because I think it traps the first time?
        let start = rawtime::Instant::now();
        let done = start.elapsed().as_nanos();
        sprintln!("rdtsc overhead: {:?} cycles", tsc2 - tsc);
        sprintln!("Instant overhead: {:?} ns", done);
        sprintln!("CPU freq: {:?} Hz", determine_cpu_frequency());

        // Note: False negatives if ran on noise machine and
        // we get unlucky with context switches are possible
        if cfg!(debug_assertions) {
            assert!(tsc2 - tsc <= 150, "rdtsc overhead big?");
            assert!(done <= 300, "Instant overhead big?");
        } else {
            assert!(tsc2 - tsc <= 100);
            assert!(done <= 150);
        }
    }
    shutdown(ExitReason::Ok);
}

/// Test timer interrupt in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
fn timer() {
    use apic::ApicDriver;
    use core::hint::spin_loop;
    use core::time::Duration;
    use log::info;

    unsafe {
        let tsc = x86::time::rdtsc();

        {
            let mut apic = crate::arch::irq::LOCAL_APIC.borrow_mut();
            apic.tsc_enable();
            apic.tsc_set(tsc + 1_000_000_000);
        }

        // Don't change this line without changing
        // `s01_timer` in s01_kernel_low_tests.rs:
        info!("Setting the timer");

        let start = rawtime::Instant::now();
        crate::arch::irq::enable();
        while start.elapsed() < Duration::from_secs(1) {
            spin_loop();
        }
        crate::arch::irq::disable();

        let _done = start.elapsed().as_nanos();
    }
    shutdown(ExitReason::Ok);
}

/// Test wrgsbase performance.
#[cfg(feature = "integration-test")]
fn wrgsbase() {
    use log::info;

    unsafe {
        let iterations = 100_000;
        let start = x86::time::rdtsc();
        for _i in 0..iterations {
            x86::current::segmentation::wrgsbase(0x1);
        }
        let end = x86::time::rdtsc();
        info!("wrgsbase cycles: {}", (end - start) / iterations)
    }
    shutdown(ExitReason::Ok);
}

/// Test the debug facility for page-faults.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
#[inline(never)]
fn pfault() {
    use crate::arch::debug;
    debug::cause_pfault();
}

/// Test the debug facility for general-protection-faults.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
fn gpfault() {
    use crate::arch::debug;
    debug::cause_gpfault();
}

/// Test allocation and deallocation of objects of various sizes.
#[cfg(feature = "integration-test")]
fn alloc() {
    use alloc::vec::Vec;
    use fallible_collections::vec::FallibleVec;
    use fallible_collections::FallibleVecGlobal;
    use log::info;

    {
        let mut buf: Vec<u8> = Vec::try_with_capacity(0).expect("Can alloc");
        // test allocation sizes from 0 .. 8192
        for i in 0..1024 {
            buf.try_push(i as u8).expect("succeeds");
        }
    } // Make sure we drop here.
    info!("small allocations work.");

    {
        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE; // 0.03 MiB, 8 pages
        let mut buf: Vec<u8> = Vec::try_with_capacity(size).expect("Can alloc");
        for i in 0..size {
            buf.try_push(i as u8).expect("succeeds");
        }

        let size: usize = x86::bits64::paging::BASE_PAGE_SIZE * 256; // 8 MiB
        let mut buf: Vec<usize> = Vec::try_with_capacity(size).expect("Can alloc");
        for i in 0..size {
            buf.try_push(i as usize).expect("succeeds");
        }
    } // Make sure we drop here.
    info!("large allocations work.");

    shutdown(ExitReason::Ok);
}

/// Checks that we can initialize ACPI, query the ACPI tables,
/// and parse the topology. The test ensures things work in case we
/// have no numa nodes.
#[cfg(feature = "integration-test")]
fn acpi_smoke() {
    use atopology::MACHINE_TOPOLOGY;

    // We have 2 cores ...
    assert_eq!(MACHINE_TOPOLOGY.num_threads(), 2);
    // ... no SMT ...
    assert_eq!(MACHINE_TOPOLOGY.num_cores(), 2);
    // ... 1 sockets ...
    assert_eq!(MACHINE_TOPOLOGY.num_packages(), 1);
    // ... no numa ...
    assert_eq!(MACHINE_TOPOLOGY.num_nodes(), 0);

    // ... and one IOAPIC which starts from GSI 0
    for (i, io_apic) in MACHINE_TOPOLOGY.io_apics().enumerate() {
        match i {
            0 => assert_eq!(io_apic.global_irq_base, 0, "GSI of I/O APIC is 0"),
            _ => assert_eq!(
                MACHINE_TOPOLOGY.io_apics().count(),
                1,
                "Found more than 1 IO APIC"
            ),
        };
    }

    shutdown(ExitReason::Ok);
}

/// Checks that we can initialize ACPI, query the ACPI tables
/// and correctly parse a large NUMA topology (8 sockets, 80 cores).
#[cfg(feature = "integration-test")]
fn acpi_topology() {
    use atopology::MACHINE_TOPOLOGY;
    use log::info;

    // We have 80 cores ...
    assert_eq!(MACHINE_TOPOLOGY.num_threads(), 80);
    // ... no SMT ...
    assert_eq!(MACHINE_TOPOLOGY.num_cores(), 80);
    // ... 8 sockets ...
    assert_eq!(MACHINE_TOPOLOGY.num_packages(), 8);
    // ... on 8 numa-nodes ...
    assert_eq!(MACHINE_TOPOLOGY.num_nodes(), 8);

    // ... with 512 MiB of RAM per NUMA node ...
    for (nid, node) in MACHINE_TOPOLOGY.nodes().enumerate() {
        match nid {
            0 => assert_eq!(
                node.memory()
                    .filter(|ma| !ma.is_non_volatile() & !ma.is_hotplug_region())
                    .count(),
                2
            ),
            _ => assert_eq!(
                node.memory()
                    .filter(|ma| !ma.is_non_volatile() & !ma.is_hotplug_region())
                    .count(),
                1
            ),
        };

        let bytes_per_node: u64 = node
            .memory()
            .map(|ma| {
                if !ma.is_non_volatile() & !ma.is_hotplug_region() {
                    ma.length
                } else {
                    0
                }
            })
            .sum();

        if nid > 0 {
            assert_eq!(
                bytes_per_node,
                1024 * 1024 * 1024,
                "Node#{} has 1 GiB of RAM",
                nid
            );
        } else {
            // First node has a bit less...
            assert!(
                bytes_per_node >= 1024 * 1024 * 1020,
                "Node#0 has almost 1 GiB of RAM"
            );
        }
    }

    // ... and 10 cores per node ...
    for node in MACHINE_TOPOLOGY.nodes() {
        assert_eq!(node.cores().count(), 10);
    }

    // ... and 10 cores/threads per package ...
    for package in MACHINE_TOPOLOGY.packages() {
        assert_eq!(package.cores().count(), 10);
        assert_eq!(package.threads().count(), 10);
    }

    // ... and each core has 9 siblings ...
    for core in MACHINE_TOPOLOGY.cores() {
        assert_eq!(core.siblings().count(), 9);
    }

    // ... and one IOAPIC which starts from GSI 0
    for (i, io_apic) in MACHINE_TOPOLOGY.io_apics().enumerate() {
        match i {
            0 => assert_eq!(io_apic.global_irq_base, 0, "GSI of I/O APIC is 0"),
            _ => assert_eq!(
                MACHINE_TOPOLOGY.io_apics().count(),
                1,
                "Found more than 1 IO APIC"
            ),
        };
    }

    info!("test-acpi-topology done.");
    shutdown(ExitReason::Ok);
}

/// Tests core booting.
///
/// Boots a single core, checks we can print from it and arguments
/// get passed along correctly.
#[cfg(feature = "integration-test")]
fn coreboot_smoke() {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    use klogger::sprintln;
    use log::info;

    use crate::arch::coreboot;
    use crate::stack::OwnedStack;

    // Entry point for app. This function is called from start_ap.S:
    fn nrk_init_ap(arg1: Arc<u64>, initialized: &AtomicBool) {
        crate::arch::enable_sse();
        crate::arch::enable_fsgsbase();

        // Check that we can pass arguments:
        assert_eq!(*arg1, 0xfefe);
        assert_eq!(initialized.load(Ordering::SeqCst), false);

        // Don't change this string otherwise the test will fail:
        sprintln!("Hello from the other side");

        initialized.store(true, Ordering::SeqCst);
        assert_eq!(initialized.load(Ordering::SeqCst), true);
        loop {}
    }

    assert_eq!(atopology::MACHINE_TOPOLOGY.num_threads(), 2, "No 2nd core?");

    let bsp_thread = atopology::MACHINE_TOPOLOGY.current_thread();
    let thread_to_boot = atopology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .expect("Didn't find an application core to boot...");

    unsafe {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        let arg: Arc<u64> = Arc::try_new(0xfefe).expect("Can't Arc this");
        coreboot::initialize(
            thread_to_boot.apic_id(),
            nrk_init_ap,
            Arc::clone(&arg),
            &initialized,
            &app_stack,
        );

        // Wait until core is up or we time out
        let timeout = x86::time::rdtsc() + 10_000_000;
        loop {
            // Did the core signal us initialization completed?
            if initialized.load(Ordering::SeqCst) {
                break;
            }

            // Have we waited long enough?
            if x86::time::rdtsc() > timeout {
                panic!("Core didn't boot properly...");
            }
        }

        assert!(initialized.load(Ordering::SeqCst));
        // Don't change this string otherwise the test will fail:
        info!("Core has started");
    }

    shutdown(ExitReason::Ok);
}

/// Tests booting of a core and using the node-replication
/// log to communicate information.
#[cfg(feature = "integration-test")]
fn coreboot_nrlog() {
    use crate::arch::coreboot;
    use crate::stack::OwnedStack;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use klogger::sprintln;
    use log::info;
    use node_replication::Log;

    let log: Arc<Log<usize>> =
        Arc::try_new(Log::<usize>::new(1024 * 1024 * 1)).expect("Can't Arc this");

    // Entry point for app. This function is called from start_ap.S:
    fn nrk_init_ap(mylog: Arc<Log<usize>>, initialized: &AtomicBool) {
        crate::arch::enable_sse();
        crate::arch::enable_fsgsbase();

        mylog.append(&[0usize, 1usize], 1, |_o: usize, _i: usize| {});
        //assert!(r.is_some());

        // Don't change this string otherwise the test will fail:
        sprintln!("Hello from the other side");

        initialized.store(true, Ordering::SeqCst);
        loop {}
    }

    assert_eq!(atopology::MACHINE_TOPOLOGY.num_threads(), 4, "Need 4 cores");

    let bsp_thread = atopology::MACHINE_TOPOLOGY.current_thread();
    let thread = atopology::MACHINE_TOPOLOGY
        .threads()
        .find(|t| t != &bsp_thread)
        .unwrap();

    unsafe {
        //for thread in threads_to_boot {
        let initialized: AtomicBool = AtomicBool::new(false);
        let app_stack = OwnedStack::new(4096 * 32);

        coreboot::initialize(
            thread.apic_id(),
            nrk_init_ap,
            log.clone(),
            &initialized,
            &app_stack,
        );

        // Wait until core is up or we time out
        let timeout = x86::time::rdtsc() + 10_000_000;
        loop {
            // Did the core signal us initialization completed?
            if initialized.load(Ordering::SeqCst) {
                break;
            }

            // Have we waited long enough?
            if x86::time::rdtsc() > timeout {
                panic!("Core didn't boot properly...");
            }
        }

        assert!(initialized.load(Ordering::SeqCst));
        // Don't change this string otherwise the test will fail:
        info!("Core has started");
    }

    shutdown(ExitReason::Ok);
}

/// Some thread local data for testing.
#[cfg(feature = "integration-test")]
#[thread_local]
pub(crate) static TLS_TEST: [core::cell::Cell<&str>; 2] =
    [core::cell::Cell::new("aaaa"), core::cell::Cell::new("efgh")];

/// Tests access to thread local storage from the BSP core.
#[cfg(feature = "integration-test")]
fn thread_local_usage() {
    assert_eq!(TLS_TEST[0].get(), "aaaa");
    assert_eq!(TLS_TEST[1].get(), "efgh");

    TLS_TEST[0].set("xxxx");

    assert_eq!(TLS_TEST[0].get(), "xxxx");
    assert_eq!(TLS_TEST[1].get(), "efgh");

    shutdown(ExitReason::Ok);
}

/// Checks that we can discover NVDIMMs, query the ACPI NFIT tables,
/// and parse the topology.
#[cfg(feature = "integration-test")]
fn nvdimm_discover() {
    use atopology::MemoryType::PERSISTENT_MEMORY;
    use atopology::MACHINE_TOPOLOGY;
    use log::info;

    let page_size: usize = x86::bits64::paging::BASE_PAGE_SIZE;
    let per_socket_pmem: usize = 512 * 1024 * 1024;

    let pmems = MACHINE_TOPOLOGY.persistent_memory();
    let nodes = MACHINE_TOPOLOGY.num_nodes();

    // We have two numa nodes
    assert_eq!(nodes, 2);

    // We have two PMEM regions.
    assert_eq!(pmems.size_hint().0, 2);

    for pmem in pmems {
        // Each region of the Persistent Memory type.
        assert_eq!(pmem.ty, PERSISTENT_MEMORY);

        // Number of pages on each socket
        assert_eq!(pmem.page_count as usize, per_socket_pmem / page_size);
    }

    info!("NVDIMMs Discovered");

    shutdown(ExitReason::Ok);
}

/// Tests that the system initializes all cores.
#[cfg(feature = "integration-test")]
fn coreboot() {
    // If we've come here the test has already completed,
    // as core initialization happens during init.
    shutdown(ExitReason::Ok);
}

/// Test process loading / user-space.
#[cfg(feature = "integration-test")]
fn userspace() {
    let binary = crate::CMDLINE.get().map_or("init", |c| c.init_binary);
    assert!(crate::arch::process::spawn(binary).is_ok());
    crate::scheduler::schedule()
}

/// Test SSE/floating point in the kernel.
#[cfg(feature = "integration-test")]
fn sse() {
    use log::info;
    info!("division = {}", 10.0 / 2.19);
    info!("division by zero = {}", 10.0 / 0.0);
    shutdown(ExitReason::Ok);
}

/// Test VSpace debugging.
#[cfg(feature = "integration-test")]
fn vspace_debug() {
    crate::graphviz::render_opts(
        &*crate::arch::vspace::INITIAL_VSPACE.lock(),
        &[crate::graphviz::RenderOption::RankDirectionLR],
    );

    shutdown(ExitReason::Ok);
}

// Careful note: If you change any of the lines order/amount/variable names etc.
// in this function, you *most likely* have to adjust s02_gdb in
// `s02_kernel_low_tests.rs`.
#[cfg(feature = "integration-test")]
fn gdb() {
    use log::info;

    //arch::irq::ioapic_establish_route(0x0, 0x0);

    // watchpoint test:
    let mut watchpoint_trigger: usize = 0;
    info!("watchpoint_trigger is {}", watchpoint_trigger);
    watchpoint_trigger = 0xdeadbeef;
    info!("watchpoint_trigger is {}", watchpoint_trigger);

    // step  through all of info:
    info!("step");
    info!("step");

    //arch::irq::enable();
    //let mut cond = true;
    //while cond {}
    //cond = false;
    //info!("cond is {}", cond);

    // continue until exit:
    shutdown(ExitReason::Ok);
}

#[cfg(feature = "integration-test")]
fn just_exit_ok() {
    shutdown(ExitReason::Ok);
}

#[cfg(feature = "integration-test")]
fn just_exit_fail() {
    shutdown(ExitReason::ReturnFromMain);
}

/// Test shootdown facilities in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
fn replica_advance() {
    use crate::arch::tlb::advance_replica;
    use log::info;

    //let _threads = atopology::MACHINE_TOPOLOGY.num_threads();

    let start = rawtime::Instant::now();
    advance_replica(0x1, 0x0);
    let _duration = start.elapsed().as_nanos();

    info!("advance-replica done?");
    loop {}
    //shutdown(ExitReason::Ok);
}

/// Test vmxnet3 integrated with smoltcp.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
fn vmxnet_smoltcp() {
    use alloc::borrow::ToOwned;
    use alloc::collections::BTreeMap;
    use alloc::{vec, vec::Vec};
    use core::cell::Cell;

    use log::{debug, info};

    use vmxnet3::pci::BarAccess;
    use vmxnet3::smoltcp::DevQueuePhy;
    use vmxnet3::vmx::VMXNet3;

    use smoltcp::iface::{InterfaceBuilder, NeighborCache};
    use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    use crate::memory::vspace::MapAction;
    use crate::memory::PAddr;
    use crate::memory::KERNEL_BASE;

    //arch::irq::ioapic_establish_route(0x0, 0x0);
    //crate::arch::irq::enable();
    const VMWARE_INC: u16 = 0x15ad;
    const VMXNET_DEV: u16 = 0x07b0;
    let vmx = if let Some(vmxnet3_dev) = crate::pci::claim_device(VMWARE_INC, VMXNET_DEV) {
        let addr = vmxnet3_dev.pci_address();
        let ba = BarAccess::new(addr.bus.into(), addr.dev.into(), addr.fun.into());
        let mut kvspace = crate::arch::vspace::INITIAL_VSPACE.lock();
        for &bar in &[ba.bar0 - KERNEL_BASE, ba.bar1 - KERNEL_BASE] {
            assert!(kvspace
                .map_identity_with_offset(
                    PAddr::from(KERNEL_BASE),
                    PAddr::from(bar),
                    0x1000,
                    MapAction::kernel() | MapAction::write(),
                )
                .is_ok());
        }

        let mut vmx = VMXNet3::new(ba, 2, 2).unwrap();
        assert!(vmx.attach_pre().is_ok());
        vmx.init();
        vmx
    } else {
        panic!("vmxnet3 PCI device not found, forgot to pass `--nic vmxnet3`?");
    };

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub(crate) struct Clock(Cell<Instant>);

    impl Clock {
        fn new() -> Clock {
            let rt = rawtime::Instant::now().as_nanos();
            let rt_millis = (rt / 1_000_000) as i64;
            Clock(Cell::new(Instant::from_millis(rt_millis)))
        }

        fn elapsed(&self) -> Instant {
            self.0.get()
        }
    }

    let device = DevQueuePhy::new(vmx).expect("Can't create PHY");
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ethernet_addr = EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xd0]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(172, 31, 0, 10), 24)];

    // Create SocketSet w/ space for 1 socket
    let mut sock_vec = Vec::new();
    sock_vec.try_reserve_exact(1).unwrap();

    let mut iface = InterfaceBuilder::new(device, sock_vec)
        .ip_addrs(ip_addrs)
        .hardware_addr(ethernet_addr.into())
        .neighbor_cache(neighbor_cache)
        .finalize();

    let tcp1_handle = iface.add_socket(tcp_socket);

    let mut tcp_6970_active = false;
    let mut done = false;
    let clock = Clock::new();
    // Don't change the next line without changing `s03_kernel_high_tests.rs`
    info!("About to serve sockets!");

    while !done && clock.elapsed() < Instant::from_millis(25_000) {
        match iface.poll(clock.elapsed()) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // tcp:6970: echo with reverse
        {
            let socket = iface.get_socket::<TcpSocket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(6970).unwrap()
            }

            if socket.is_active() && !tcp_6970_active {
                info!("tcp:6970 connected");
            } else if !socket.is_active() && tcp_6970_active {
                debug!("tcp:6970 disconnected");
                done = true;
            }
            tcp_6970_active = socket.is_active();

            if socket.may_recv() {
                let data = socket
                    .recv(|buffer| (buffer.len(), buffer.to_owned()))
                    .unwrap();
                if socket.can_send() && !data.is_empty() {
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                info!("tcp:6970 close");
                socket.close();
                done = true;
            }
        }
    }

    shutdown(ExitReason::Ok);
}

/// Test cxl device in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
pub(crate) fn cxl_write() {
    use crate::memory::KERNEL_BASE;
    use crate::transport::shmem::SHMEM;

    lazy_static::initialize(&SHMEM);

    let mut buffer_content: u8 = 0x0;
    for device in SHMEM.devices.iter() {
        buffer_content += 1;
        for i in 0..(device.region.size / 1024) {
            let region = (device.region.base.as_u64() + KERNEL_BASE + (i * 1024) as u64) as *mut u8;
            unsafe { core::ptr::write(region, buffer_content) };
        }
    }
    shutdown(ExitReason::Ok);
}

/// Test cxl device in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
pub(crate) fn cxl_read() {
    use crate::memory::KERNEL_BASE;
    use crate::transport::shmem::SHMEM;

    lazy_static::initialize(&SHMEM);

    let mut buffer_content: u8 = 0x0;
    for device in SHMEM.devices.iter() {
        buffer_content += 1;
        for i in 0..(device.region.size / 1024) {
            let region = (device.region.base.as_u64() + KERNEL_BASE + (i * 1024) as u64) as *mut u8;
            let read = unsafe { core::ptr::read(region) };
            assert_eq!(read, buffer_content);
        }
    }

    shutdown(ExitReason::Ok);
}

/// Test cxl device in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
pub(crate) fn shmem_interruptor() {
    use crate::arch::irq::REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR;
    use crate::transport::shmem::SHMEM;

    lazy_static::initialize(&SHMEM);
    {
        // The ivshmem server allocates IDs consecutively, so we'll assume interruptee is
        // current_id - 1
        log::info!(
            "Sending shmem interrupt to: {:?} on vector {:?}",
            SHMEM.devices[0].id - 1,
            1
        );
        SHMEM.devices[0].set_doorbell(
            REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR,
            SHMEM.devices[0].id - 1,
        );
    }
    shutdown(ExitReason::Ok);
}

/// Test cxl device in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
pub(crate) fn shmem_interruptee() {
    use core::hint::spin_loop;
    use core::time::Duration;

    use crate::arch::irq::{REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR, REMOTE_TLB_WORK_PENDING_VECTOR};
    use crate::transport::shmem::SHMEM;

    lazy_static::initialize(&SHMEM);

    SHMEM.get_interrupt_device().unwrap().enable_msix_vector(
        REMOTE_TLB_WORK_PENDING_SHMEM_VECTOR as usize,
        0,
        REMOTE_TLB_WORK_PENDING_VECTOR,
    );

    let start = rawtime::Instant::now();
    crate::arch::irq::enable();
    while start.elapsed() < Duration::from_secs(60) {
        spin_loop();
    }
    crate::arch::irq::disable();
    let _done = start.elapsed().as_nanos();

    shutdown(ExitReason::Ok);
}

/// Test shootdown facilities in the kernel.
#[cfg(all(feature = "integration-test", target_arch = "x86_64"))]
fn shootdown_simple() {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::hint::spin_loop;

    use apic::ApicDriver;
    use fallible_collections::vec::FallibleVec;
    use fallible_collections::FallibleVecGlobal;
    use log::info;
    use x86::apic::{
        ApicId, DeliveryMode, DeliveryStatus, DestinationMode, DestinationShorthand, Icr, Level,
        TriggerMode,
    };

    use crate::arch;

    let threads = atopology::MACHINE_TOPOLOGY.num_threads();

    unsafe {
        let start = rawtime::Instant::now();

        let mut shootdowns = Vec::try_with_capacity(threads).expect("succeeds");
        for t in atopology::MACHINE_TOPOLOGY.threads() {
            let id = t.apic_id();
            info!(
                "{:?} logical {:?} cluster {:?} cluster rel. logical {:?}",
                id,
                id.x2apic_logical_id(),
                id.x2apic_logical_cluster_id(),
                id.x2apic_logical_cluster_address(),
            );
            let shootdown =
                Arc::try_new(arch::tlb::Shootdown::new(0x1000..0x2000)).expect("succeeds");
            arch::tlb::enqueue(t.id, arch::tlb::WorkItem::Shootdown(shootdown.clone()));
            shootdowns.try_push(shootdown).expect("succeeds");
        }

        {
            let mut apic = crate::arch::irq::LOCAL_APIC.borrow_mut();
            let vector = 251;
            let icr = Icr::for_x2apic(
                vector,
                ApicId::X2Apic(0b1_1111_1111_1111_1111),
                DestinationShorthand::NoShorthand,
                DeliveryMode::Fixed,
                DestinationMode::Logical,
                DeliveryStatus::Idle,
                Level::Assert,
                TriggerMode::Edge,
            );

            apic.send_ipi(icr)
        }

        for shootdown in shootdowns {
            if !shootdown.is_acknowledged() {
                spin_loop();
            }
        }
        let duration = start.elapsed().as_nanos();

        info!("name,cores,shootdown_duration_ns");
        info!("shootdown-simple,{},{}", threads, duration);
    }
    shutdown(ExitReason::Ok);
}
