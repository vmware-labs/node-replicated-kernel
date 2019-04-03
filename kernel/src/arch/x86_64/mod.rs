use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::transmute;
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
pub mod memory;
pub mod process;
pub mod syscall;

pub mod acpi;
mod exec;
mod isr;
mod sse;
mod start;

use crate::main;
use crate::memory::*;
use crate::ExitReason;
use klogger;
use log::Level;

use memory::*;
use process::*;

extern "C" {
    #[no_mangle]
    static mboot_ptr: memory::PAddr;

    #[no_mangle]
    pub static mut init_pd: paging::PD;
}

use spin::Mutex;
pub static KERNEL_BINARY: Mutex<Option<&'static [u8]>> = Mutex::new(None);

use logos::Logos;

#[derive(Logos, Debug, PartialEq, Clone, Copy)]
enum CmdToken {
    // Logos requires that we define two default variants,
    // one for end of input source,
    #[end]
    End,

    #[regex = "./[a-zA-Z]+"]
    Binary,

    #[token = " "]
    ArgSeparator,

    // Anything not properly encoded
    #[error]
    Error,

    // Tokens can be literal strings, of any length.
    #[token = "log="]
    Log,

    // Or regular expressions.
    #[regex = "[a-zA-Z]+"]
    Text,
}

#[no_mangle]
pub extern "C" fn bespin_init_ap() {
    sprint!("Hello from the other side\n\n");
    loop {}
}

#[lang = "start"]
#[no_mangle]
fn bespin_arch_init(_rust_main: *const u8, _argc: isize, _argv: *const *const u8) -> isize {
    sprint!("\n\n");
    sse::initialize();
    lazy_static::initialize(&rawtime::arch::tsc::TSC_FREQUENCY);

    let mb = unsafe {
        Multiboot::new(mboot_ptr.into(), |base, size| {
            let vbase = memory::paddr_to_kernel_vaddr(PAddr::from(base)).as_ptr();
            Some(slice::from_raw_parts(vbase, size))
        })
        .unwrap()
    };

    let args = mb.command_line().unwrap_or("./mbkernel");
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
            (CmdToken::End, _) => level = Level::Error,
            (_, _) => continue,
        };

        break level;
    };

    klogger::init(level).expect("Can't set-up logging");

    // It's important that these two constructs get evaluated early during boot.
    info!(
        "Started at {} with {:?} since CPU startup",
        *rawtime::WALL_TIME_ANCHOR,
        *rawtime::BOOT_TIME_ANCHOR
    );

    // For lineup scheduler enable fs/gs base instructions (Thread local storage implementation).
    let mut cr4: controlregs::Cr4 = unsafe { controlregs::cr4() };
    cr4 |= controlregs::Cr4::CR4_ENABLE_FSGSBASE;
    unsafe { controlregs::cr4_write(cr4) };

    debug::init();

    if mb.modules().is_some() {
        for module in mb.modules().unwrap() {
            debug!("Found module {:?}", module);
            if module.string.is_some() && module.string.unwrap() == "kernel" {
                unsafe {
                    let mut k = KERNEL_BINARY.lock();
                    let binary = slice::from_raw_parts(
                        memory::paddr_to_kernel_vaddr(PAddr::from(module.start)).as_ptr(),
                        (module.end - module.start) as usize,
                    );
                    *k = Some(binary);
                }
            }
        }
    }

    debug!("checking memory regions");
    unsafe {
        mb.memory_regions().map(|regions| {
            for region in regions {
                if region.memory_type() == MemoryType::Available {
                    if region.base_address() > 0 {
                        // XXX: Regions contain kernel image as well insetad of just RAM, that's why we add 20 MiB to it...
                        let offset = 1024 * 1024 * 30;
                        let base = PAddr::from(region.base_address() + offset);
                        let size = region.length() - offset;
                        debug!("Traing to add base {:?} size {:?}", base, size);
                        if FMANAGER.add_memory(Frame::new(base, size as usize)) {
                            debug!("Added {:?}", region);
                        } else {
                            warn!("Unable to add {:?}", region)
                        }
                    } else {
                        debug!("Ignore BIOS mappings at {:?}", region);
                    }
                }
            }
        });

        FMANAGER.init();
        FMANAGER.print_info();
    }

    let cpuid = cpuid::CpuId::new();
    let fi = cpuid.get_feature_info();
    let has_x2apic = match fi {
        Some(ref fi) => fi.has_x2apic(),
        None => false,
    };
    let has_tsc = match fi {
        Some(ref fi) => fi.has_tsc(),
        None => false,
    };

    irq::setup_idt();
    irq::enable();
    gdt::setup_gdt();

    if has_x2apic && has_tsc && false {
        //info!("x2APIC / deadline TSC supported!");
        let mut apic = x2apic::X2APIC::new();
        apic.attach();
        info!(
            "x2APIC id: {}, version: {}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );
    } else {
        info!("no x2APIC support. Use xAPIC instead.");
        use crate::memory::BespinPageTableProvider;
        use x86::msr::{rdmsr, IA32_APIC_BASE};

        let cr_three: u64 = unsafe { controlregs::cr3() };
        let pml4: PAddr = PAddr::from_u64(cr_three);
        let pml4_table = unsafe { transmute::<VAddr, &mut PML4>(paddr_to_kernel_vaddr(pml4)) };
        let mut vspace: VSpace = VSpace {
            pml4: pml4_table,
            pager: BespinPageTableProvider::new(),
        };

        let base = unsafe {
            let mut base = rdmsr(IA32_APIC_BASE);
            debug!("xAPIC MMIO base is at {:x}", base & !0xfff);
            base & !0xfff
        };

        vspace.map_identity(VAddr::from(base), VAddr::from(base) + BASE_PAGE_SIZE);

        let regs: &'static mut [u32] =
            unsafe { core::slice::from_raw_parts_mut(base as *mut _, 256) };

        let mut apic = xapic::XAPIC::new(regs);
        apic.attach();
        info!(
            "xAPIC id: {}, version: {:#x}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );

        const X86_64_REAL_MODE_SEGMENT: u16 = 0x0600;
        let real_mode_page = X86_64_REAL_MODE_SEGMENT >> 8;
        let real_mode_linear_offset = X86_64_REAL_MODE_SEGMENT << 4;

        extern "C" {
            static x86_64_start_ap: *const u8;
            static x86_64_start_ap_end: *const u8;
            static x86_64_init_ap_absolute_entry: *mut fn();
        };
        let boot_code_size = unsafe { (x86_64_start_ap).offset_from(x86_64_start_ap_end) as usize };

        unsafe {
            let start_addr: usize = core::mem::transmute(&x86_64_start_ap);
            let end_addr: usize = core::mem::transmute(&x86_64_start_ap_end);
            let boot_code_size = end_addr - start_addr;
            info!("boot_code_size = {:#x}", boot_code_size);

            let real_mode_base: usize = 0x0 + real_mode_linear_offset as usize;
            info!("real_mode_base = {:#x}", real_mode_base);
            let ap_bootstrap_code: &'static [u8] = unsafe {
                core::slice::from_raw_parts(
                    &x86_64_start_ap as *const _ as *const u8,
                    boot_code_size,
                )
            };
            let real_mode_destination: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(real_mode_base as *mut u8, boot_code_size)
            };

            let entry_pointer: *mut u64 = core::mem::transmute(&x86_64_init_ap_absolute_entry);
            *entry_pointer = bespin_init_ap as u64;

            vspace.map_identity(
                VAddr::from(real_mode_base),
                VAddr::from(real_mode_base) + 20 * BASE_PAGE_SIZE,
            );

            real_mode_destination.copy_from_slice(ap_bootstrap_code);

            info!("x86_64_start_ap = {:p} {:#x}", &x86_64_start_ap, start_addr);
            info!(
                "x86_64_start_ap = {:p} {:#x}",
                &x86_64_start_ap_end, end_addr
            );
        }

        // Have fun launching some cores:
        unsafe {
            apic.ipi_init();
            apic.ipi_init_deassert();

            apic.ipi_startup(real_mode_page as u8);
            info!("Cores should've started?");
        }
    };

    debug!("allocation should work here...");
    let mut process_list: Vec<Box<process::Process>> = Vec::with_capacity(100);
    let init = Box::new(process::Process::new(1).unwrap());
    process_list.push(init);

    // No we go in the arch-independent part
    main();

    debug!("Returned from main, shutting down...");
    debug::shutdown(ExitReason::ReturnFromMain);
}
