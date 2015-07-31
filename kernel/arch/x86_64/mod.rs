#[macro_use]
pub use ::mutex;

pub mod memory;
pub mod debug;
pub mod apic;
pub mod irq;
pub mod process;
pub mod gdt;
pub mod syscall;

extern crate core;
use prelude::*;
use core::mem::{transmute, size_of};
use core::slice;
use core::ops::DerefMut;

use x86::paging;
use multiboot::{Multiboot, MemoryType};

extern {
    #[no_mangle]
    static mboot_ptr: memory::PAddr;

    #[no_mangle]
    static mut init_pd: paging::PD;

    #[no_mangle]
    static mut init_pml4: paging::PML4;

    //#[no_mangle]
    //static mboot_sig: PAddr;
}

use elfloader::{ElfLoader};
use mm;
use x86::cpuid;
use elfloader;
use collections::{Vec};
//use allocator;

#[cfg(target_arch="x86_64")]
#[lang="start"]
#[no_mangle]
pub fn arch_init() {
    log!("Started");

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
        log!("x2APIC / deadline TSC supported!");
        unsafe {
            log!("enable APIC");
            let apic = apic::x2APIC::new();
            //apic.enable_tsc();
            //apic.set_tsc(rdtsc()+1000);
            log!("APIC is bsp: {}", apic.is_bsp());
        }
    }
    else {
        log!("no x2APIC support. Continuing without interrupts.")
    }

    unsafe {
        let mut base = 0x0;
        for e in &mut init_pd.iter_mut() {
            (*e) = paging::PDEntry::new(base, paging::PD_P | paging::PD_RW | paging::PD_PS);
            base += 1024*1024*2;
        }
    }


    let mut fm = mm::fmanager.lock();
    let mb = Multiboot::new(mboot_ptr,  memory::paddr_to_kernel_vaddr);
    mb.memory_regions().map(|regions| {
        for region in regions {
            if region.memory_type() == MemoryType::RAM {
                fm.add_region(region.base_address(), region.length());
            }
        }
    });
    fm.clean_regions();
    fm.print_regions();

    //let mut entries = Vec::with_capacity(10);
    //entries.push(1);



    mb.modules().map(|modules| {
        for module in modules {
            log!("Found module {:?}", module);
            let binary: &'static [u8] = unsafe {
                core::slice::from_raw_parts(
                    transmute::<usize, *const u8>(module.start),
                    module.start - module.end)
            };

            let mut cp = process::current_process.lock();
            (*cp) = process::Process::new(0);

            match *cp.deref_mut() {
                Some(ref mut p) => {
                    elfloader::ElfBinary::new(module.string, binary).map(|e| {
                        // Patch in the kernel tables...
                        unsafe {
                            p.vspace.pml4[511] = init_pml4[511];
                        }
                        e.load(p);
                        p.start(0x4000f0);
                    });
                },
                None => (),
            }
        }
    });

/*
    match *cp.deref_mut() {
        Some(ref mut p) => {
            let mod_cb = | name, start, end | {
                log!("Found module {}: {:x} - {:x}", name, start, end);

                let binary: &'static [u8] = unsafe {
                    core::slice::from_raw_parts(
                        transmute::<usize, *const u8>(start),
                        start - end)
                };

                match elfloader::ElfBinary::new(name, binary) {
                    Some(e) =>
                    {
                        // Patch in the kernel tables...
                        unsafe {
                            p.vspace.pml4[511] = init_pml4[511];
                        }
                        e.load(p);
                        p.start(0x4000f0);
                    },
                    None => ()
                };
            };
            //multiboot.find_modules(mod_cb);
        }
        None => ()
    };*/


    loop {}
}