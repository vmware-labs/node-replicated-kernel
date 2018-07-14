//#[macro_use]
//pub use ::mutex;

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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::transmute;
use core::ops::DerefMut;
use core::slice;

use x86::bits64::paging;
use x86::cpuid;

use elfloader;
use multiboot::{MemoryType, Multiboot};

use main;
use mm::FMANAGER;

extern "C" {
    #[no_mangle]
    static mboot_ptr: memory::PAddr;

    #[no_mangle]
    static mut init_pd: paging::PD;

    #[no_mangle]
    static mut init_pml4: paging::PML4;

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

#[lang = "start"]
#[no_mangle]
#[start]
pub fn arch_init() {
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
        let mut base = 0x0;
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
        Multiboot::new(mboot_ptr, |base, size| {
            let vbase = memory::paddr_to_kernel_vaddr(base) as *const u8;
            Some(slice::from_raw_parts(vbase, size))
        }).unwrap()
    };

    slog!("checking memory regions");
    unsafe {
        mb.memory_regions().map(|regions| {
            for region in regions {
                if region.memory_type() == MemoryType::Available {
                    slog!("ADding region {:?}", region);
                    FMANAGER.add_region(region.base_address(), region.length());
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

    //let s = Stack::new();
    //slog!("s.start {:?}, s.end {:?}", s.start(), s.end());
    //let c = Context::new(init, arg, start, s);

    mb.modules().map(|modules| {
        for module in modules {
            slog!("Found module {:?}", module);
            let binary: &'static [u8] = unsafe {
                slice::from_raw_parts(
                    transmute::<u64, *const u8>(module.start),
                    (module.start - module.end) as usize,
                )
            };

            let mut cp = process::CURRENT_PROCESS.lock();
            (*cp) = process::Process::new(0);

            match *cp.deref_mut() {
                Some(ref mut p) => {
                    elfloader::ElfBinary::new(module.string.unwrap(), binary).map(|e| {
                        // Patch in the kernel tables...
                        unsafe {
                            p.vspace.pml4[511] = init_pml4[511];
                        }
                        e.load(p);
                        p.start(0x4000f0);
                    });
                }
                None => (),
            }
        }
    });

    // No we go in the arch-independent part
    main();

    // and never return from there
    unreachable!();
}
