//#[macro_use]
//pub use ::mutex;

extern crate core;

pub mod memory;
pub mod debug;
pub mod apic;
pub mod irq;
pub mod process;
pub mod gdt;
pub mod syscall;
pub mod threads;


use core::mem::{transmute};
use core::ops::DerefMut;

use ::{kmain};
use x86::paging;
use multiboot::{Multiboot, MemoryType};

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

use elfloader::{ElfLoader};
use mm::{fmanager, BespinSlabsProvider};
use slabmalloc::{ZoneAllocator};
use x86::cpuid;
use elfloader;
use collections::{Vec};
use allocator;
use alloc::boxed::Box;

fn initialize_memory(mb: &Multiboot) {
    unsafe {
        mb.memory_regions().map(|regions| {
            for region in regions {
                if region.memory_type() == MemoryType::RAM {
                    fmanager.add_region(region.base_address(), region.length());
                }
            }
        });

        fmanager.clean_regions();
        fmanager.print_regions();
    }
}

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
            let apic = apic::X2APIC::new();
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

    let mb = Multiboot::new(mboot_ptr,  memory::paddr_to_kernel_vaddr);
    initialize_memory(&mb);

    let mut bp = BespinSlabsProvider;
    let mut za: ZoneAllocator;

    unsafe {
        let provider = transmute::<&mut BespinSlabsProvider, &'static mut BespinSlabsProvider>(&mut bp);
        za = ZoneAllocator::new(Some(provider));
        let allocator = transmute::<&mut ZoneAllocator, &'static mut ZoneAllocator>(&mut za);
        allocator::zone_allocator = Some(allocator);
    }

    let mut process_list: Vec<Box<process::Process>> = Vec::with_capacity(100);
    let init = Box::new(process::Process::new(1).unwrap());


    process_list.push(init);

    mb.modules().map(|modules| {
        for module in modules {
            log!("Found module {:?}", module);
            let binary: &'static [u8] = unsafe {
                core::slice::from_raw_parts(
                    transmute::<usize, *const u8>(module.start),
                    module.start - module.end)
            };

            let mut cp = process::CURRENT_PROCESS.lock();
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

    // No we go in the arch-independent part
    kmain();

    // and never return from there
    unreachable!();
}