//! Contains initialization code for x86-64 cores.
//! The purpose of the arch specific part is to initialize the machine to
//! a sane environment and then jump to the main() function.
use alloc::boxed::Box;
use alloc::vec::Vec;

use core::cmp;
use core::mem::{size_of, transmute};
use core::slice;

use driverkit::DriverControl;

use multiboot::{MemoryType, Multiboot};
use x86::bits64::paging;
use x86::bits64::paging::{PAddr, VAddr, PML4};
use x86::controlregs;
use x86::cpuid;

use apic::x2apic;
use apic::xapic;

pub mod debug;
pub mod gdt;
pub mod irq;
pub mod kcb;
pub mod memory;
pub mod process;
pub mod syscall;

pub mod acpi;
mod exec;
mod isr;
mod start;

use crate::memory::*;
use crate::{xmain, ExitReason};
use klogger;
use log::Level;
use logos::Logos;

use memory::*;
use process::*;
extern "C" {
    /// A pointer to the multiboot struct (initialized by start.S)
    #[no_mangle]
    static mboot_ptr: memory::PAddr;
}

use spin::Mutex;
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

/// Entry point for AP (non bootstrap core). This function is called
/// from start_ap.S for any core except core 0.
#[no_mangle]
pub extern "C" fn bespin_init_ap() {
    sprint!("Hello from the other side\n\n");
    loop {}
}

/// Given physical a base and size returns a slice of the memory region
/// in virtual memory.
/// Used by multiboot since it stores everything as physical addresses.debug
///
/// Example: base 0x4770000 and len 10 will return slice [u8; 10] at
/// address 0xffffffff84770000.
fn paddr_to_slice(base: u64, size: usize) -> Option<&'static [u8]> {
    let vbase = memory::paddr_to_kernel_vaddr(PAddr::from(base)).as_ptr();
    unsafe { Some(slice::from_raw_parts(vbase, size)) }
}

/// Parse command line argument and initialize the logging infrastructure.
///
/// Example: If args is './mbkernel log=trace' -> sets level to Level::debug
fn init_logging(args: &str) {
    let mut lexer = CmdToken::lexer(args);
    let level: Level = loop {
        let mut level = Level::Info;
        lexer.advance();
        match (lexer.token, lexer.slice()) {
            (CmdToken::Binary, bin) => assert_eq!(bin, "./mbkernel"),
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
            (CmdToken::End, _) => level = Level::Trace,
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
    let has_avx = fi.as_ref().map_or(false, |f| f.has_avx());
    let has_osfxsr = fi.as_ref().map_or(false, |f| f.has_fxsave_fxstor());

    assert!(has_tsc, "No RDTSC? Run on a more modern machine!");
    assert!(has_sse, "No SSE? Run on a more modern machine!");
    assert!(has_osfxsr, "No fxsave? Run on a more modern machine!");
    assert!(has_sse3, "No SSE3? Run on a more modern machine!"); //TBD
    assert!(has_avx, "No AVX? Run on a more modern machine!"); //TBD

    assert!(has_apic, "No APIC? Run on a more modern machine!");
    assert!(has_x2apic, "No x2apic? Run on a more modern machine!");
    assert!(has_syscalls, "No sysenter? Run on a more modern machine!");
    assert!(has_pae, "No PAE? Run on a more modern machine!");
    assert!(has_msr, "No MSR? Run on a more modern machine!");
}

/// Enable SSE functionality and disable the old x87 FPU.
/// (yes this goes against conventional
/// wisdom that thinks SSE instructions in the
/// kernel are a bad idea)
fn enable_sse() {
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
fn enable_fsgsbase() {
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
/// the currently loaded PML4 table which is defined in start.S
/// see `.globl init_pml4`
fn find_current_vspace() -> VSpace<'static> {
    let cr_three: u64 = unsafe { controlregs::cr3() };
    let pml4: PAddr = PAddr::from_u64(cr_three);
    let pml4_table = unsafe { transmute::<VAddr, &mut PML4>(paddr_to_kernel_vaddr(pml4)) };
    VSpace {
        pml4: pml4_table,
        pager: crate::memory::BespinPageTableProvider::new(),
    }
}

/// Return the base address of the xAPIC (x86 Interrupt controller)
fn find_apic_base() -> u64 {
    use x86::msr::{rdmsr, IA32_APIC_BASE};
    unsafe {
        let mut base = rdmsr(IA32_APIC_BASE);
        debug!("xAPIC MMIO base is at {:x}", base & !0xfff);
        base & !0xfff
    }
}

/// Entry function that is callsed from start.S after the pre-initialization (in assembly)
/// is done. At this point we are in x86-64 (long) mode,
/// We have a simple GDT, address space, and small stack set-up.
/// Ignore the arguments here (they are garbage).
#[lang = "start"]
#[no_mangle]
fn bespin_arch_init(_rust_main: *const u8, _argc: isize, _argv: *const *const u8) -> isize {
    sprint!("\n\n");

    enable_sse();
    enable_fsgsbase();
    gdt::setup_gdt();

    // Make sure these constants are initialized early, for proper time accounting (otherwise because
    // they are lazy_static we may not end up using them until way later).
    lazy_static::initialize(&rawtime::WALL_TIME_ANCHOR);
    lazy_static::initialize(&rawtime::BOOT_TIME_ANCHOR);

    // Construct a multiboot struct for accessing the multiboot information
    let mb = unsafe { Multiboot::new(mboot_ptr.into(), paddr_to_slice).unwrap() };
    let args = mb.command_line().unwrap_or("./mbkernel");

    init_logging(args);
    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // Figure out what this machine supports,
    // fail if it doesn't have what we need.
    assert_required_cpu_features();

    // Initializes the serial console.
    // (this is already done in a very basic form by klogger/init_logging())
    debug::init();

    // Find the kernel binary within the multiboot modules (to later store it in the KCB)
    // The binary is useful for symbol name lookups when printing stacktraces
    // in case things go wrong (see panic.rs).
    // Note: this code will refuse to start in case the kernel binary is not found
    let kernel = mb
        .modules()
        .expect("No modules found in multiboot.")
        .find(|m| m.string.is_some() && m.string.unwrap() == "kernel");

    let kernel_binary: &'static [u8] = unsafe {
        kernel.map_or(slice::from_raw_parts(0 as *mut _, 1024), |k| {
            slice::from_raw_parts(
                memory::paddr_to_kernel_vaddr(PAddr::from(k.start)).as_ptr(),
                (k.end - k.start) as usize,
            )
        })
    };

    // Find the physical memory regions available and add them to the physical memory manager
    let mut fmanager = crate::memory::buddy::BuddyFrameAllocator::new();

    // Multiboot is kept somewhere in free (low) memory but the memory regions
    // multiboot reports as free do not really take this into account,
    // so we try to find out the last address used by multiboot in order
    // to not overwrite the multiboot data later...
    let ram_start = mb.find_highest_address();
    trace!("multiboot ends at {:#x}", ram_start);

    debug!("Finding RAM regions");
    mb.memory_regions().map(|regions| {
        for region in regions {
            if region.memory_type() == MemoryType::Available {
                if region.base_address() > 0 && region.length() > (BASE_PAGE_SIZE as u64) {
                    debug!(
                        "region.base_address()={:#x} region.length()={:#x}",
                        region.base_address(),
                        region.length()
                    );

                    let (base, size) = if region.base_address() < ram_start
                        && (region.base_address() + region.length()) > ram_start
                    {
                        let cut_away = ram_start - region.base_address();
                        (ram_start, region.length() - cut_away)
                    } else {
                        (region.base_address(), region.length())
                    };

                    unsafe {
                        if fmanager.add_memory(Frame::new(PAddr::from(base), size as usize)) {
                            debug!("Trying to add base={:#x} size={:#x}", base, size);
                        } else {
                            warn!("Unable to add base={:#x} size={:#x}", base, size)
                        }
                    }
                } else {
                    debug!("Ignore memory region at {:?}", region);
                }
            }
        }
    });
    trace!("added memory regions");

    let mut vspace = find_current_vspace();
    trace!("vspace found");

    // Construct the driver object to manipulate the interrupt controller (XAPIC)
    // This is done as follows:
    // First, we find the memory for the registers of the controller (APIC base)
    // Then, we give the memory location to the APIC struct
    // Finally we put the driver in the KCB
    // Ugly: We are not quite done since regs is not yet accessible
    // but we can't map it before we have set up the KCB (see below :/)
    let base = find_apic_base();
    trace!("find_apic_base {:#x}", base);

    let regs: &'static mut [u32] = unsafe { core::slice::from_raw_parts_mut(base as *mut _, 256) };
    let mut apic = xapic::XAPIC::new(regs);
    trace!("apic constructed");

    // Construct the Kcb so we can access these things later on in the code
    let mut kcb = kcb::Kcb::new(mb, kernel_binary, vspace, fmanager, apic);
    trace!("seting kcb");
    kcb::init_kcb(kcb);
    debug!("Memory allocation should work at this point...");

    // Finish ACPI initialization here: because the APIC base memory
    // (`regs`) is not mapped, we map it now (after we do init_kcb) because
    // only then do we have memory management to allocate the page-tables
    // required for the mapping
    kcb::get_kcb()
        .init_vspace()
        .map_identity(VAddr::from(base), VAddr::from(base) + BASE_PAGE_SIZE);
    // Attach the driver to the registers:
    let mut apic = kcb::get_kcb().apic();
    apic.attach();
    info!(
        "xAPIC id: {}, version: {:#x}, is bsp: {}",
        apic.id(),
        apic.version(),
        apic.bsp()
    );

    // Initialize IDT and load a new GDT
    irq::setup_idt();

    // Do we want to enable IRQs here?
    // irq::enable();

    // No we go in the arch-independent part
    xmain();

    debug!("Returned from main, shutting down...");
    debug::shutdown(ExitReason::ReturnFromMain);
}
