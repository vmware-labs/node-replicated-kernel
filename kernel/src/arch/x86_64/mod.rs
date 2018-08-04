use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::transmute;
use core::slice;

use multiboot::{MemoryType, Multiboot};
use x86::bits64::paging;
use x86::bits64::paging::PAddr;
use x86::cpuid;

pub mod apic;
pub mod debug;
pub mod gdt;
pub mod irq;
pub mod memory;
pub mod process;
pub mod syscall;

mod exec;
mod isr;
mod start;

use main;
use mm::FMANAGER;
use ExitReason;

extern "C" {
    #[no_mangle]
    static mboot_ptr: memory::PAddr;

    #[no_mangle]
    static mut init_pd: paging::PD;

//#[no_mangle]
//static mut init_pml4: paging::PML4;

//#[no_mangle]
//static mboot_sig: PAddr;
}

/*
unsafe fn initialize_memory<'a, F: Fn(u64, usize) -> Option<&'a [u8]>>(mb: &Multiboot<F>) {
    mb.memory_regions().map(|regions| {
        for region in regions {
            if region.memory_type() == MemoryType::RAM {
                fmanager.add_region(region.base_address(), region.length());
            }
        }
    });

    fmanager.clean_regions();
    fmanager.print_regions();
}*/
use spin::Mutex;
pub static KERNEL_BINARY: Mutex<Option<&'static [u8]>> = Mutex::new(None);

#[cfg(not(test))]
#[lang = "start"]
#[no_mangle]
#[start]
pub fn arch_init() {
    sprint!("\n\n");
    slog!("Started");

    let cpuid = cpuid::CpuId::new();

    debug::init();
    irq::setup_idt();
    irq::enable();
    gdt::setup_gdt();

    let fi = cpuid.get_feature_info();
    let has_x2apic = match fi {
        Some(ref fi) => fi.has_x2apic(),
        None => false,
    };
    let has_tsc = match fi {
        Some(ref fi) => fi.has_tsc(),
        None => false,
    };

    if has_x2apic && has_tsc {
        slog!("x2APIC / deadline TSC supported!");
        slog!("enable APIC");
        let apic = apic::X2APIC::new();
        //apic.enable_tsc();
        //apic.set_tsc(rdtsc()+1000);
        slog!("APIC is bsp: {}", apic.is_bsp());
    } else {
        slog!("no x2APIC support. Continuing without interrupts.")
    }

    unsafe {
        let mut base = PAddr::from(0x0);
        for e in &mut init_pd.iter_mut() {
            (*e) = paging::PDEntry::new(
                base,
                paging::PDEntry::P | paging::PDEntry::RW | paging::PDEntry::PS,
            );
            base += 1024 * 1024 * 2;
        }
    }
    slog!("mb init");

    let mb = unsafe {
        Multiboot::new(mboot_ptr.into(), |base, size| {
            let vbase = memory::paddr_to_kernel_vaddr(PAddr::from(base)).as_ptr();
            Some(slice::from_raw_parts(vbase, size))
        }).unwrap()
    };

    if mb.modules().is_some() {
        for module in mb.modules().unwrap() {
            slog!("Found module {:?}", module);
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

    slog!("checking memory regions");
    unsafe {
        mb.memory_regions().map(|regions| {
            for region in regions {
                if region.memory_type() == MemoryType::Available {
                    if region.base_address() > 0 {
                        slog!("Adding {:?}", region);
                        FMANAGER.add_region(
                            // XXX: Regions contain kernel image as well insetad of just RAM, that's why we add 10 MiB to it...
                            PAddr::from(region.base_address() + 1024 * 1024 * 10),
                            region.length(),
                        );
                    } else {
                        slog!("Ignore BIOS mappings at {:?}", region);
                    }
                }
            }
        });
        slog!("cleaning memory regions");
        FMANAGER.clean_regions();
        slog!("print regions");
        FMANAGER.print_regions();
    }

    slog!("allocation should work here...");
    let mut process_list: Vec<Box<process::Process>> = Vec::with_capacity(100);
    let init = Box::new(process::Process::new(1).unwrap());
    process_list.push(init);

    // No we go in the arch-independent part
    main();

    slog!("Returned from main, shutting down...");
    debug::shutdown(ExitReason::ReturnFromMain);

    // and never return from there
    unreachable!();
}
