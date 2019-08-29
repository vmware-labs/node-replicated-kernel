use super::{c_int, c_uint, c_ulong, c_void};
use crate::arch::memory::{kernel_vaddr_to_paddr, PAddr, VAddr};
use crate::arch::vspace::{MapAction, VSpace};
use crate::kcb::{get_kcb, Kcb};
use crate::memory::PhysicalAllocator;
use alloc::boxed::Box;
use core::alloc::Layout;
use core::cell::RefMut;
use core::fmt;
use core::ptr;

use log::trace;
use x86::io;

static PCI_CONF_ADDR: u16 = 0xcf8;
static PCI_CONF_DATA: u16 = 0xcfc;

#[inline]
fn pci_bus_address(bus: u32, dev: u32, fun: u32, reg: i32) -> u32 {
    assert!(reg <= 0xfc);

    (1 << 31) | (bus << 16) | (dev << 11) | (fun << 8) | (reg as u32 & 0xfc)
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_iospace_init() -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_confread(
    bus: c_uint,
    dev: c_uint,
    fun: c_uint,
    reg: c_int,
    value: *mut c_uint,
) -> c_int {
    let addr = pci_bus_address(bus, dev, fun, reg);

    io::outl(PCI_CONF_ADDR, addr);
    *value = io::inl(PCI_CONF_DATA);
    trace!(
        "rumpcomp_pci_confread ({:#x} {:#x} {:#x}) reg({}) val = {:#x}",
        bus,
        dev,
        fun,
        reg,
        *value
    );

    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_confwrite(
    bus: c_uint,
    dev: c_uint,
    fun: c_uint,
    reg: c_int,
    value: c_uint,
) -> c_int {
    trace!(
        "rumpcomp_pci_confwrite ({:#x} {:#x} {:#x}) reg({:#x}) = value({:#x})",
        bus,
        dev,
        fun,
        reg,
        value
    );

    let addr = pci_bus_address(bus, dev, fun, reg);
    io::outl(PCI_CONF_ADDR, addr);
    io::outl(PCI_CONF_DATA, value);
    0
}

#[derive(Debug, Copy, Clone)]
struct RumpIRQ {
    tuple: (c_uint, c_uint, c_uint),
    vector: c_int,
    cookie: c_uint,
    handler: Option<unsafe extern "C" fn(arg: *mut c_void) -> c_int>,
    arg: *mut c_void,
}

static mut IRQS: [RumpIRQ; 32] = [RumpIRQ {
    tuple: (0, 0, 0),
    vector: 0,
    cookie: 0,
    handler: None,
    arg: ptr::null_mut(),
}; 32];

//int rumpcomp_pci_irq_map(unsigned bus, unsigned device, unsigned fun, int intrline, unsigned cookie)
#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_irq_map(
    bus: c_uint,
    dev: c_uint,
    fun: c_uint,
    vector: c_int,
    cookie: c_uint,
) -> c_int {
    error!(
        "rumpcomp_pci_irq_map for ({:#x} {:#x} {:#x}) IRQ={:#x} {:#x}",
        bus, dev, fun, vector, cookie
    );
    IRQS[0].tuple = (bus, dev, fun);
    IRQS[0].vector = vector;
    IRQS[0].cookie = cookie;

    use crate::arch::acpi;
    use crate::arch::vspace::MapAction;
    use crate::memory::{paddr_to_kernel_vaddr, PAddr, VAddr};

    for io_apic in acpi::IO_APICS.iter() {
        info!("io_apic {:?}", io_apic);
        let addr = PAddr::from(io_apic.address as u64);

        // map it
        use crate::round_up;
        crate::kcb::try_get_kcb().map(|k| {
            let mut vspace = k.init_vspace();
            vspace.map_identity_with_offset(
                PAddr::from(crate::arch::memory::KERNEL_BASE),
                addr,
                addr + x86::bits64::paging::BASE_PAGE_SIZE,
                MapAction::ReadWriteKernel,
            );
        });

        let mut inst = unsafe { apic::ioapic::IoApic::new(paddr_to_kernel_vaddr(addr).as_usize()) };
        info!("this ioapic supports {} intrs", inst.supported_interrupts());

        for i in 0..inst.supported_interrupts() {
            if (io_apic.global_irq_base + i as u32) < 16 {
                //&& i as c_int == vector {
                info!("map irq {}", i);
                if i != 2 && i != 1 {
                    inst.enable(i, 0);
                }
            }
        }
    }

    0
}

#[allow(unused)]
pub(crate) unsafe extern "C" fn irq_handler(_arg1: *mut u8) -> *mut u8 {
    let s = lineup::tls::Environment::scheduler();
    let upcalls = s.rump_upcalls as *const super::RumpHyperUpcalls;

    (*upcalls).hyp_schedule.expect("rump_upcalls set")();
    (*upcalls).hyp_lwproc_newlwp.expect("rump_upcalls set")(0);
    (*upcalls).hyp_unschedule.expect("rump_upcalls set")();

    let mut nlock: i32 = 1;
    loop {
        x86::irq::disable();

        super::rumpkern_sched(&nlock, None);
        let _r = (IRQS[0].handler.unwrap())(IRQS[0].arg as *mut u64);
        //assert_eq!(r, 0, "IRQ handler should return 0?");
        super::rumpkern_unsched(&mut nlock, None);

        crate::arch::irq::acknowledge();
        x86::irq::enable();

        let thread = lineup::tls::Environment::thread();
        thread.block(); // Wake up on next IRQ
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_irq_establish(
    cookie: c_uint,
    handler: Option<unsafe extern "C" fn(arg: *mut c_void) -> c_int>,
    arg: *mut c_void,
) -> *mut c_void {
    trace!("rumpcomp_pci_irq_establish {:#x} {:p}", cookie, arg);
    IRQS[0].handler = handler;
    IRQS[0].arg = arg;
    warn!("register for IRQ {}", IRQS[0].vector as usize + 31);

    let _unique_ptr = ptr::Unique::new(arg);

    crate::arch::irq::register_handler(
        IRQS[0].vector as usize + 31,
        Box::new(move |_| {
            let scheduler = lineup::tls::Environment::scheduler();
            scheduler.add_to_runlist(lineup::ThreadId(1));
        }),
    );

    //ptr::null_mut()
    &mut IRQS[0] as *mut _ as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_map(addr: c_ulong, len: c_ulong) -> *mut c_void {
    trace!("rumpcomp_pci_map {:#x} {:#x}", addr, len);
    //let vaddr = VAddr::from(addr);
    //let paddr = kernel_vaddr_to_paddr(vaddr);
    // 19625676584 [TRACE] - bespin::rumprt::dev: rumpcomp_pci_map 0xfeb80000 0x20000

    let mut vspace: RefMut<VSpace> = get_kcb().init_vspace();

    let start = PAddr::from(addr);
    let end = PAddr::from(addr) + len;
    vspace.map_identity(start, end, MapAction::ReadWriteKernel);

    return addr as *mut c_void;
}

// Return PAddr for VAddr
#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_virt_to_mach(vaddr: *mut c_void) -> c_ulong {
    let vaddr = VAddr::from(vaddr as u64);
    let paddr = kernel_vaddr_to_paddr(vaddr);
    trace!(
        "rumpcomp_pci_virt_to_mach va:{:#x} -> pa:{:#x}",
        vaddr,
        paddr
    );
    paddr.as_u64()
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_dmalloc(
    size: usize,
    alignment: usize,
    pptr: *mut c_ulong,
    vptr: *mut c_ulong,
) -> c_int {
    trace!("rumpcomp_pci_dmalloc");
    let layout = Layout::from_size_align(size, alignment);
    let kcb = get_kcb();
    let mut fmanager = kcb.pmanager();

    match layout {
        Ok(l) => fmanager.allocate(l).map_or(2, |frame| {
            let vaddr = frame.kernel_vaddr();
            *vptr = vaddr.as_u64();
            *pptr = frame.base.as_u64();
            error!(
                "rumpcomp_pci_dmalloc {:#x} {:#x} at va:{:#x} pa:{:#x}",
                size,
                alignment,
                vaddr.as_u64(),
                frame.base.as_u64()
            );

            0
        }),
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_dmafree(addr: c_ulong, size: usize) {
    error!("rumpcomp_pci_dmafree {:#x} {:#x}", addr, size);
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rumpcomp_pci_dmaseg {
    pub ds_pa: c_ulong,
    pub ds_len: c_ulong,
    pub ds_vacookie: c_ulong,
}

impl fmt::Debug for rumpcomp_pci_dmaseg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "rumpcomp_pci_dmaseg {{ ds_pa: {:#x}, ds_len: {}, ds_vacookie: {:#x} }}",
            self.ds_pa, self.ds_len, self.ds_vacookie
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_dmamem_map(
    dss: *mut rumpcomp_pci_dmaseg,
    nseg: usize,
    totlen: usize,
    vap: *mut *mut c_void,
) -> c_int {
    trace!(
        "rumpcomp_pci_dmamem_map {:#x} {:#x} {:?}",
        nseg,
        totlen,
        &mut (*dss)
    );

    if nseg <= 1 {
        *vap = ((*dss).ds_vacookie) as *mut c_void;
        //trace!("rumpcomp_pci_dmamem_map vap={:p}", *vap);
        0
    } else {
        1
    }
}
