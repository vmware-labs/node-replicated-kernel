// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{c_int, c_uint, c_ulong, c_void};

use core::alloc::Layout;
use core::{fmt, ptr};

use hashbrown::HashMap;
use lineup::core_id_to_index;
use lineup::tls2::Environment;
use log::{error, trace};
use spin::Mutex;
use x86::current::paging::{PAddr, VAddr};
use x86::io;

static PCI_CONF_ADDR: u16 = 0xcf8;
static PCI_CONF_DATA: u16 = 0xcfc;

static CONFSPACE_LOCK: Mutex<()> = Mutex::new(());
static PADDR_CACHE: Mutex<Option<HashMap<VAddr, PAddr>>> = Mutex::new(None);

#[inline]
fn pci_bus_address(bus: u32, dev: u32, fun: u32, reg: i32) -> u32 {
    assert!(reg <= 0xfc);

    (1 << 31) | (bus << 16) | (dev << 11) | (fun << 8) | (reg as u32 & 0xfc)
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_iospace_init() -> c_int {
    PADDR_CACHE.lock().replace(HashMap::new());
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
    // This is a hack - for rackscale, we want to ignore all devices
    if Environment::scheduler().core_id > kpi::process::MAX_CORES {
        return 0;
    }

    let addr = pci_bus_address(bus, dev, fun, reg);

    let _l = CONFSPACE_LOCK.lock();
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
    // This is a hack - for rackscale, we want to ignore all devices
    if Environment::scheduler().core_id > kpi::process::MAX_CORES {
        return 0;
    }
    trace!(
        "rumpcomp_pci_confwrite ({:#x} {:#x} {:#x}) reg({:#x}) = value({:#x})",
        bus,
        dev,
        fun,
        reg,
        value
    );

    let addr = pci_bus_address(bus, dev, fun, reg);
    let _l = CONFSPACE_LOCK.lock();
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
    trace!(
        "rumpcomp_pci_irq_map for ({:#x} {:#x} {:#x}) IRQ={:#x} {:#x}",
        bus,
        dev,
        fun,
        vector,
        cookie
    );
    IRQS[0].tuple = (bus, dev, fun);
    IRQS[0].vector = vector;
    IRQS[0].cookie = cookie;

    let cur_thread = lineup::tls2::Environment::thread();
    cur_thread
        .spawn_irq_thread(
            Some(irq_handler),
            core::ptr::null_mut(),
            cur_thread.current_core,
            vector as u64 + 32,
        )
        .expect("Can't create IRQ thread?");

    crate::syscalls::Irq::irqalloc(vector as u64, cur_thread.current_core as u64).ok();

    0
}

#[allow(unused)]
pub unsafe extern "C" fn irq_handler(_arg1: *mut u8) -> *mut u8 {
    let s = lineup::tls2::Environment::scheduler();
    let upcalls = s.rump_upcalls.load(core::sync::atomic::Ordering::Relaxed)
        as *const super::RumpHyperUpcalls;

    (*upcalls).hyp_schedule.expect("rump_upcalls set")();
    (*upcalls).hyp_lwproc_newlwp.expect("rump_upcalls set")(0);
    (*upcalls).hyp_unschedule.expect("rump_upcalls set")();
    trace!("irq_handler");

    let thread = lineup::tls2::Environment::thread();
    thread.block(); // Wake up on next IRQ

    let mut nlock: i32 = 1;
    loop {
        let start = rawtime::Instant::now();
        super::rumpkern_sched(&nlock, None);
        let r = (IRQS[0].handler.unwrap())(IRQS[0].arg as *mut u64);
        //assert_eq!(r, 1, "IRQ handler should return 1 (I don't actually know)?");
        super::rumpkern_unsched(&mut nlock, None);

        let thread = lineup::tls2::Environment::thread();
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
    trace!("register for IRQ {}", IRQS[0].vector as usize + 32);

    &mut IRQS[0] as *mut _ as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_map(addr: c_ulong, len: c_ulong) -> *mut c_void {
    error!("rumpcomp_pci_map {:#x} {:#x}", addr, len);

    let start = PAddr::from(addr);

    let r = crate::syscalls::VSpace::map_device(start.as_u64(), len as u64);

    match r {
        Ok((vaddr, _paddr)) => vaddr.as_u64() as *mut c_void,
        Err(_e) => ptr::null_mut(),
    }
}

// Return PAddr for VAddr
#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_virt_to_mach(vaddr: *mut c_void) -> c_ulong {
    let vaddr = VAddr::from(vaddr as u64);

    fn identify(vaddr: VAddr) -> PAddr {
        let (_, paddr) = unsafe {
            crate::syscalls::VSpace::identify(vaddr.align_down_to_base_page().into()).unwrap()
        };
        let paddr_aligned = paddr + vaddr.base_page_offset();

        trace!(
            "rumpcomp_pci_virt_to_mach va:{:#x} -> pa:{:#x}",
            vaddr,
            paddr_aligned
        );

        PAddr::from(paddr_aligned)
    }

    PADDR_CACHE
        .lock()
        .as_mut()
        .map_or_else(
            || identify(vaddr),
            |ht| {
                if let Some(paddr) = ht.get(&vaddr.align_down_to_base_page()) {
                    let paddr_aligned = *paddr + vaddr.base_page_offset();
                    PAddr::from(paddr_aligned)
                } else {
                    let paddr = identify(vaddr);
                    ht.insert(
                        vaddr.align_down_to_base_page(),
                        paddr.align_down_to_base_page(),
                    );
                    paddr
                }
            },
        )
        .as_u64()
}

#[no_mangle]
pub unsafe extern "C" fn rumpcomp_pci_dmalloc(
    size: usize,
    alignment: usize,
    pptr: *mut c_ulong,
    vptr: *mut c_ulong,
) -> c_int {
    assert!(
        size <= 2 * 1024 * 1024,
        "Can't handle anything above 2 MiB (needs to be consecutive physically)"
    );
    let size = if size > 4096 { 2 * 1024 * 1024 } else { 4096 };
    trace!("rumpcomp_pci_dmalloc adjusted size {} to", size);

    let layout = Layout::from_size_align_unchecked(size, size);

    let r = {
        let mut p = crate::mem::PAGER[core_id_to_index(Environment::core_id())].lock();
        (*p).allocate(layout)
    };

    match r {
        Ok((vaddr, paddr)) => {
            *vptr = vaddr.as_u64();
            *pptr = paddr.as_u64();
            PADDR_CACHE.lock().as_mut().map(|ht| {
                ht.insert(vaddr, paddr);
            });

            trace!(
                "rumpcomp_pci_dmalloc {:#x} {:#x} at va:{:#x} -- {:#x} pa:{:#x} -- {:#x}",
                size,
                alignment,
                vaddr.as_usize(),
                vaddr.as_usize() + size,
                paddr.as_usize(),
                paddr.as_usize() + size,
            );

            0
        }
        Err(_e) => 1,
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
    error!(
        "rumpcomp_pci_dmamem_map {:#x} {:#x} {:?}",
        nseg,
        totlen,
        &(*dss)
    );

    if nseg <= 1 {
        *vap = ((*dss).ds_vacookie) as *mut c_void;
        //trace!("rumpcomp_pci_dmamem_map vap={:p}", *vap);
        0
    } else {
        panic!("nseg > 1")
    }
}
