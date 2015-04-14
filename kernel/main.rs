#![feature(no_std)]	//< unwind needs to define lang items
#![feature(lang_items)]	//< unwind needs to define lang items
#![feature(asm)]	//< As a kernel, we need inline assembly
#![feature(core)]	//< libcore (see below) is not yet stablized
#![feature(intrinsics)]
#![no_std]	//< Kernels can't use std

use prelude::*;

#[macro_use]
extern crate core;
extern crate rlib;

#[cfg(target_arch="x86_64")]
extern crate multiboot;
#[cfg(target_arch="x86_64")]
extern crate cpuid;
#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate x86;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate klogger;

#[cfg(target_arch="x86_64")]
#[macro_use]
extern crate elfloader;

pub use klogger::*;

mod prelude;
pub mod unwind;
use core::mem::{transmute, size_of};
use core::raw;


#[cfg(target_arch="x86_64")] #[path="arch/x86_64/mod.rs"]
pub mod arch;

mod mm;

use multiboot::{SIGNATURE_RAX, Multiboot};

use x86::msr::{wrmsr, rdmsr};
use x86::time::{rdtsc};
use x86::irq;
use x86::controlregs;

use arch::apic;
use arch::memory::{PAddr, VAddr};
use arch::irq::{setup_idt};
use arch::debug;

extern {
    #[no_mangle]
    static mboot_ptr: PAddr;

    #[no_mangle]
    static mboot_sig: PAddr;
}

/// Kernel entrypoint
#[lang="start"]
#[no_mangle]
pub fn kmain()
{
    log!("Started");

    let mut fm = mm::FrameManager::new();
    if mboot_sig == SIGNATURE_RAX {
        let multiboot = Multiboot::new(mboot_ptr,  mm::paddr_to_kernel_vaddr);
        let cb = | base, size, mtype | { fm.add_multiboot_region(base, size, mtype); };
        multiboot.find_memory(cb);
        let mod_cb = | name, start, end | {
            log!("Found module {}: {:x} - {:x}", name, start, end);

            let slice = unsafe { raw::Slice { data: transmute::<u64, *const u8>(start), len: (start as usize) - (end as usize) } };
            let byte_array: &'static [u8] = unsafe { transmute(slice) };
            elfloader::parse_elf(byte_array);
        };
        multiboot.find_modules(mod_cb);
    }
    fm.clean_regions();
    fm.print_regions();

    let frame = fm.allocate_frame();
    log!("frame = {:?}", frame);
    fm.print_regions();

    let cpuid = cpuid::CpuId::new();


    unsafe {
        log!("set-up IDT");
        setup_idt();

        log!("irq enable");


        irq::enable();
        debug::init();
    }

    log!("cpuid[1] = {:?}", cpuid.get(1));
    let has_x2apic = cpuid.get(1).ecx & 1<<21 > 0;
    let has_tsc = cpuid.get(1).ecx & 1<<24 > 0;
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
        int!(3);

        loop {
            //for i in 1..100000000 { }
            //log!("doing stuff... {}", controlregs::cr3());
        }
    }


}

