//! Contains initialization code for x86-64 cores.
//! The purpose of the arch specific part is to initialize the machine to
//! a sane environment and then jump to the main() function.
use alloc::boxed::Box;
use alloc::sync::Arc;

use core::alloc::Layout;
use core::mem::transmute;
use core::slice;
use core::sync::atomic::{AtomicBool, Ordering};

use driverkit::DriverControl;

use x86::apic::ApicControl;
use x86::bits64::paging::{PAddr, VAddr, PML4};
use x86::controlregs;
use x86::cpuid;

//use apic::x2apic;
use apic::xapic;

pub mod coreboot;
pub mod debug;
pub mod gdt;
pub mod irq;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod syscall;
pub mod vspace;

use uefi::table::boot::MemoryType;

pub mod acpi;
mod isr;

use klogger;
use log::Level;
use logos::Logos;
use spin::Mutex;

use crate::memory::*;
use crate::stack::{OwnedStack, Stack};
use crate::{xmain, ExitReason};

use memory::*;
use vspace::*;

pub static KERNEL_BINARY: Mutex<Option<&'static [u8]>> = Mutex::new(None);

/// Definition to parse the kernel command-line arguments.
#[derive(Logos, Debug, PartialEq, Clone, Copy)]
enum CmdToken {
    /// Logos requires that we define two default variants,
    /// one for end of input source,
    #[end]
    End,

    /// Binary name
    #[regex = "./[a-zA-Z]+"]
    Binary,

    /// Argument separator (1 space)
    #[token = " "]
    ArgSeparator,

    /// Anything not properly encoded
    #[error]
    Error,

    /// Log token.
    #[token = "log="]
    Log,

    /// Regular expressions for parsing log-level.
    #[regex = "[a-zA-Z]+"]
    Text,
}

/// Parse command line argument and initialize the logging infrastructure.
///
/// Example: If args is './kernel log=trace' -> sets level to Level::Trace
fn init_logging(args: &str) {
    let mut lexer = CmdToken::lexer(args);
    let level: Level = loop {
        let mut level = Level::Info;
        lexer.advance();
        match (lexer.token, lexer.slice()) {
            (CmdToken::Binary, bin) => assert_eq!(bin, "./kernel"),
            (CmdToken::Log, _) => {
                lexer.advance();
                level = match (lexer.token, lexer.slice()) {
                    (CmdToken::Text, "trace") => Level::Trace,
                    (CmdToken::Text, "debug") => Level::Debug,
                    (CmdToken::Text, "info") => Level::Info,
                    (CmdToken::Text, "warn") => Level::Warn,
                    (CmdToken::Text, "error") => Level::Error,
                    (_, _) => Level::Error,
                };
            }
            (CmdToken::End, _) => level = Level::Info,
            (_, _) => continue,
        };

        break level;
    };

    klogger::init(level).expect("Can't set-up logging");
}

/// Make sure the machine supports what we require.
fn assert_required_cpu_features() {
    let cpuid = cpuid::CpuId::new();
    let fi = cpuid.get_feature_info();
    let has_apic = fi.as_ref().map_or(false, |f| f.has_apic());
    let has_x2apic = fi.as_ref().map_or(false, |f| f.has_x2apic());
    let has_tsc = fi.as_ref().map_or(false, |f| f.has_tsc());
    let has_syscalls = fi.as_ref().map_or(false, |f| f.has_sysenter_sysexit());
    let has_pae = fi.as_ref().map_or(false, |f| f.has_pae());
    let has_msr = fi.as_ref().map_or(false, |f| f.has_msr());

    let has_sse = fi.as_ref().map_or(false, |f| f.has_sse());
    let has_sse3 = fi.as_ref().map_or(false, |f| f.has_sse3());
    let _has_avx = fi.as_ref().map_or(false, |f| f.has_avx());
    let has_osfxsr = fi.as_ref().map_or(false, |f| f.has_fxsave_fxstor());

    assert!(has_tsc, "No RDTSC? Run on a more modern machine!");
    assert!(has_sse, "No SSE? Run on a more modern machine!");
    assert!(has_osfxsr, "No fxsave? Run on a more modern machine!");
    assert!(has_sse3, "No SSE3? Run on a more modern machine!"); //TBD

    //assert!(has_avx, "No AVX? Run on a more modern machine!");

    assert!(has_apic, "No APIC? Run on a more modern machine!");
    assert!(has_x2apic, "No X2APIC? Run on a more modern machine!");
    assert!(has_syscalls, "No sysenter? Run on a more modern machine!");
    assert!(has_pae, "No PAE? Run on a more modern machine!");
    assert!(has_msr, "No MSR? Run on a more modern machine!");
}

/// Enable SSE functionality and disable the old x87 FPU.
/// (yes this goes against conventional
/// wisdom that thinks SSE instructions in the
/// kernel are a bad idea)
///
/// # TODO
/// This is public because of the integration tests (and ideally shouldn't be).
pub fn enable_sse() {
    // Follow the protocol described in Intel SDM, 13.1.3 Initialization of the SSE Extensions
    unsafe {
        let mut cr4 = controlregs::cr4();
        // Operating system provides facilities for saving and restoring SSE state
        // using FXSAVE and FXRSTOR instructions
        cr4 |= controlregs::Cr4::CR4_ENABLE_SSE;
        // The operating system provides a SIMD floating-point exception (#XM) handler
        //cr4 |= x86::controlregs::Cr4::CR4_UNMASKED_SSE;
        controlregs::cr4_write(cr4);

        let mut cr0 = controlregs::cr0();
        // Disables emulation of the x87 FPU
        cr0 &= !controlregs::Cr0::CR0_EMULATE_COPROCESSOR;
        // Required for Intel 64 and IA-32 processors that support the SSE
        cr0 |= controlregs::Cr0::CR0_MONITOR_COPROCESSOR;
        controlregs::cr0_write(cr0);
    }
}

/// For our scheduler and KCB we enable the fs/gs base instructions on the machine
/// This allows us to conventiently read and write the fs and gs registers
/// with 64 bit values (otherwise it's a bit of a pain)
/// (used for our thread local storage implementation).
///
/// # TODO
/// This is public because of the integration tests (and ideally shouldn't be).
pub fn enable_fsgsbase() {
    unsafe {
        let mut cr4: controlregs::Cr4 = controlregs::cr4();
        cr4 |= controlregs::Cr4::CR4_ENABLE_FSGSBASE;
        controlregs::cr4_write(cr4)
    };
}

/// Return a struct to the currently installed page-tables so we
/// can manipulate them (for example to map the APIC registers).
///
/// This function is called during initialization.
/// It will read the cr3 register to find the physical address of
/// the currently loaded PML4 table which is constructed
/// by the bootloader.
///
/// # Safety
/// This should only be called once during init to retrieve the
/// initial VSpace.
unsafe fn find_current_vspace() -> VSpace {
    let cr_three: u64 = controlregs::cr3();
    let pml4: PAddr = PAddr::from(cr_three);
    let pml4_table = transmute::<VAddr, *mut PML4>(paddr_to_kernel_vaddr(pml4));
    VSpace {
        pml4: Box::into_pin(Box::from_raw(pml4_table)),
    }
}

/// Return the base address of the xAPIC (x86 Interrupt controller)
fn find_apic_base() -> u64 {
    use x86::msr::{rdmsr, IA32_APIC_BASE};
    unsafe {
        let base = rdmsr(IA32_APIC_BASE);
        debug!("xAPIC MMIO base is at {:x}", base & !0xfff);
        base & !0xfff
    }
}

// Includes structs KernelArgs, and Module from bootloader
include!("../../../../bootloader/src/shared.rs");

struct AppCoreArgs {
    mem_region: Frame,
    kernel_binary: &'static [u8],
    kernel_args: &'static KernelArgs<[Module; 2]>,
}

/// Entry point for application cores. This is normally called from `start_ap.S`.
///
/// This is almost identical to `_start` which is initializing the BSP core
/// (and called from UEFI instead).
fn start_app_core(args: Arc<AppCoreArgs>, initialized: &AtomicBool) {
    enable_sse();
    enable_fsgsbase();
    assert_required_cpu_features();

    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };

    let mut fmanager = crate::memory::buddy::BuddyFrameAllocator::new();
    unsafe {
        fmanager.add_memory(args.mem_region);
    }

    let vspace = unsafe { find_current_vspace() }; // Safe, done once during init

    let base = find_apic_base();
    trace!("find_apic_base {:#x}", base);
    let regs: &'static mut [u32] = unsafe { core::slice::from_raw_parts_mut(base as *mut _, 256) };
    let mut apic = xapic::XAPICDriver::new(regs);
    apic.attach();

    let mut kcb = kcb::Kcb::new(args.kernel_args, args.kernel_binary, vspace, fmanager, apic);

    kcb::init_kcb(&mut kcb);
    kcb.set_interrupt_stack(OwnedStack::new(64 * BASE_PAGE_SIZE));
    kcb.set_syscall_stack(OwnedStack::new(64 * BASE_PAGE_SIZE));
    kcb.set_save_area(Box::pin(kpi::x86_64::SaveArea::empty()));

    core::mem::forget(kcb);

    debug!("Memory allocation should work at this point...");

    // Set up interrupts (which needs Box)
    //irq::init_irq_handlers();

    // Attach the driver to the registers:
    {
        let apic = kcb::get_kcb().apic();
        info!(
            "xAPIC id: {}, version: {:#x}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );
    } // Make sure to drop the reference to the APIC again

    initialized.store(true, Ordering::SeqCst);
    loop {
        unsafe { x86::halt() };
    }
}

/// Initialize the rest of the cores in the system.
///
/// # Notes
/// Dependencies for calling this function are:
///  - Initialized ACPI
///  - Initialized topology
///  - Local APIC driver
fn boot_app_cores(kernel_binary: &'static [u8], kernel_args: &'static KernelArgs<[Module; 2]>) {
    let bsp_thread = topology::MACHINE_TOPOLOGY.current_thread();

    // There should be different strategies
    // replica_mapping_strategy = { per_thread, per_core, per_packet, per_numa_node }
    // replica_executor_strategy = { flatcombining, master_delegation }

    // For now just boot everything, except ourselves
    // Create a single log and one replica...
    let threads_to_boot = topology::MACHINE_TOPOLOGY
        .threads()
        .filter(|t| t != &bsp_thread);

    for thread in threads_to_boot {
        trace!("Booting {:?}", thread);

        use topology;
        use x86::apic::{ApicControl, ApicId};

        // A simple stack for the app core (non bootstrap core)
        let coreboot_stack: OwnedStack = OwnedStack::new(4096 * 32);

        let k = kcb::get_kcb();
        let mem_region = unsafe {
            k.pmanager()
                .allocate(Layout::from_size_align_unchecked(1024 * 1024 * 2, 0x1000))
                .unwrap()
        };

        let initialized: AtomicBool = AtomicBool::new(false);
        let arg: Arc<AppCoreArgs> = Arc::new(AppCoreArgs {
            mem_region,
            kernel_binary,
            kernel_args,
        });

        unsafe {
            coreboot::initialize(
                thread.apic_id(),
                start_app_core,
                arg.clone(),
                &initialized,
                &coreboot_stack,
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
                    panic!("Core {:?} didn't boot properly...", thread.apic_id());
                }
            }
        }

        assert!(initialized.load(Ordering::SeqCst));
        info!("Core {:?} has started", thread.apic_id());
    }
}

/// Entry function that is called from UEFI
/// At this point we are in x86-64 (long) mode,
/// We have a simple GDT, our address space, and stack set-up.
/// The argc argument is abused as a pointer ot the KernelArgs struct
/// passed by UEFI.
#[lang = "start"]
#[no_mangle]
#[start]
fn _start(argc: isize, _argv: *const *const u8) -> isize {
    sprint!("\r\n");

    enable_sse();
    enable_fsgsbase();
    unsafe {
        gdt::setup_early_gdt();
        irq::setup_early_idt();
    };

    // Make sure these constants are initialized early, for proper time accounting (otherwise because
    // they are lazy_static we may not end up using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // Parse the command line arguments
    // TODO: This should be passed on over using the UEFI bootloader
    // https://stackoverflow.com/questions/17702725/how-to-access-command-line-arguments-in-uefi
    let args = include_str!("../../../cmdline.in");
    init_logging(args);
    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // At this point we should be able to handle exceptions:
    #[cfg(all(feature = "test-pfault-early"))]
    debug::cause_pfault();
    #[cfg(all(feature = "test-gpfault-early"))]
    debug::cause_gpfault();

    // Load a new GDT and initialize our IDT
    syscall::enable_fast_syscalls();

    // We should catch page-faults and general protection faults from here...

    let kernel_args: &'static KernelArgs<[Module; 2]> =
        unsafe { transmute::<u64, &'static KernelArgs<[Module; 2]>>(argc as u64) };

    // TODO(fix): Because we pnly have a borrow of KernelArgs we have to work too hard to get mm_iter
    let mm_iter = unsafe {
        let mut mm_iter: uefi::table::boot::MemoryMapIter<'static> = core::mem::uninitialized();
        core::ptr::copy_nonoverlapping(
            &kernel_args.mm_iter as *const uefi::table::boot::MemoryMapIter,
            &mut mm_iter as *mut uefi::table::boot::MemoryMapIter,
            1,
        );
        mm_iter
    };

    // Figure out what this machine supports,
    // fail if it doesn't have what we need.
    assert_required_cpu_features();

    // Initializes the serial console.
    // (this is already done in a very basic form by klogger/init_logging())
    debug::init();

    // Get the kernel binary (to later store it in the KCB)
    // The binary is useful for symbol name lookups when printing stacktraces
    // in case things go wrong (see panic.rs).
    info!("Kernel binary: {:?}", kernel_args.modules[0]);
    let kernel_binary: &'static [u8] = unsafe {
        slice::from_raw_parts(
            kernel_args.modules[0].base().as_u64() as *const u8,
            kernel_args.modules[0].size(),
        )
    };

    // Find the physical memory regions available and add them to the physical memory manager
    let mut fmanager = crate::memory::buddy::BuddyFrameAllocator::new();
    debug!("Finding RAM regions");
    for region in mm_iter {
        trace!("{:?}", region);
        if region.ty == MemoryType::CONVENTIONAL {
            let base = region.phys_start;
            let size: usize = region.page_count as usize * BASE_PAGE_SIZE;

            // TODO BAD: We can only add one region to the buddy allocator, so we need
            // to pick a big one weee
            if base > 0x100000 && size > BASE_PAGE_SIZE && region.page_count > 12000 {
                debug!("region.base = {:#x} region.size = {:#x}", base, size);
                unsafe {
                    let f = Frame::new(PAddr::from(base), size);
                    if fmanager.add_memory(f) {
                        debug!("Added base={:#x} size={:#x}", base, size);
                    } else {
                        warn!("Unable to add base={:#x} size={:#x}", base, size)
                    }
                }
            } else {
                debug!("Ignore memory region at {:?}", region);
            }
        }
    }
    trace!("added memory regions");

    let vspace = unsafe { find_current_vspace() }; // Safe, done once during init
    trace!("vspace found");

    // Construct the driver object to manipulate the interrupt controller (XAPIC)
    let base = find_apic_base();
    trace!("find_apic_base {:#x}", base);
    let regs: &'static mut [u32] = unsafe { core::slice::from_raw_parts_mut(base as *mut _, 256) };
    let mut apic = xapic::XAPICDriver::new(regs);
    apic.attach();

    // Construct the Kcb so we can access these things later on in the code
    let mut kcb = kcb::Kcb::new(kernel_args, kernel_binary, vspace, fmanager, apic);
    kcb::init_kcb(&mut kcb);
    debug!("Memory allocation should work at this point...");

    // Let's finish KCB initialization (easier as we have alloc now):
    kcb.set_interrupt_stack(OwnedStack::new(64 * BASE_PAGE_SIZE));
    kcb.set_syscall_stack(OwnedStack::new(64 * BASE_PAGE_SIZE));
    kcb.set_save_area(Box::pin(kpi::x86_64::SaveArea::empty()));
    kcb.finalize();

    // Make sure we don't drop the KCB and anything in it,
    // the kcb is on the init stack and remains allocated on it,
    // this is (probably) fine as we never reclaim this stack or
    // return to _start.
    core::mem::forget(kcb);

    // Set up interrupts (which needs Box)
    irq::init_irq_handlers();

    // Attach the driver to the registers:
    {
        let apic = kcb::get_kcb().apic();
        info!(
            "xAPIC id: {}, version: {:#x}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );
    } // Make sure to drop the reference to the APIC again

    // Init ACPI
    {
        let r = acpi::init();
        assert!(r.is_ok());
    }

    // Needs ACPI and alloc
    lazy_static::initialize(&topology::MACHINE_TOPOLOGY);
    //info!("{:#?}", *topology::MACHINE_TOPOLOGY);

    // Bring up the rest of the system
    #[cfg(not(feature = "bsp-only"))]
    boot_app_cores(kernel_binary, kernel_args);

    // Done with initialization, now we go in
    // the arch-independent part:
    xmain();

    debug!("Returned from main, shutting down...");
    debug::shutdown(ExitReason::ReturnFromMain);
}
