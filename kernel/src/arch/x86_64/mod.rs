use alloc::boxed::Box;
use alloc::vec::Vec;
use core::slice;

use driverkit::DriverControl;

use multiboot::{MemoryType, Multiboot};
use x86::bits64::paging;
use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE, PML4};
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

mod exec;
mod isr;
mod sse;
mod start;

use core::mem::transmute;

use self::memory::paddr_to_kernel_vaddr;
use self::process::VSpace;

use klogger;
use log::Level;
use main;
use memory::{Frame, PhysicalAllocator, FMANAGER};
use ExitReason;

extern "C" {
    #[no_mangle]
    static mboot_ptr: memory::PAddr;

    #[no_mangle]
    pub static mut init_pd: paging::PD;

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

#[lang = "start"]
#[no_mangle]
fn arch_init(_rust_main: *const u8, _argc: isize, _argv: *const *const u8) -> isize {
    sse::initialize();
    sprint!("\n\n");
    klogger::init(Level::Trace).expect("Can't set-up logging");
    debug!("Started");

    debug::init();
    irq::setup_idt();
    irq::enable();
    gdt::setup_gdt();

    unsafe {
        let mut base = PAddr::from(0x0);
        let mut page_cnt = 0;

        for e in &mut init_pd.iter_mut() {
            (*e) = paging::PDEntry::new(
                base,
                paging::PDFlags::P | paging::PDFlags::RW | paging::PDFlags::PS,
            );

            base += 1024 * 1024 * 2;

            page_cnt += 1;

            //debug!("{:?}", (*e) );
            //debug!("e ptr {:p}", e);
        }

        debug!(
            "mb init. allocated {:?} PDE pages; base offset {:?}",
            page_cnt, base
        );
    }

    let mb = unsafe {
        Multiboot::new(mboot_ptr.into(), |base, size| {
            let vbase = memory::paddr_to_kernel_vaddr(PAddr::from(base)).as_ptr();
            Some(slice::from_raw_parts(vbase, size))
        })
        .unwrap()
    };

    trace!("{}", mb.command_line().unwrap_or("def"));

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
                        // XXX: Regions contain kernel image as well insetad of just RAM, that's why we add 10 MiB to it...
                        let offset = 1024 * 1024 * 10;
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

    if has_x2apic && has_tsc {
        debug!("x2APIC / deadline TSC supported!");
        debug!("enable APIC");
        let mut apic = x2apic::X2APIC::new();
        apic.attach();
        //apic.enable_tsc();
        //apic.set_tsc(rdtsc()+1000);
        debug!(
            "xAPIC id: {}, version: {}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );
    } else {
        debug!("no x2APIC support. Use xAPIC instead.");
        use memory::BespinPageTableProvider;
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
        debug!(
            "xAPIC id: {}, version: {:#x}, is bsp: {}",
            apic.id(),
            apic.version(),
            apic.bsp()
        );
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
