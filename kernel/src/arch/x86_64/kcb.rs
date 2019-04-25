// LKCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{RefCell, RefMut};
use core::ptr;

use multiboot::Multiboot;
use x86::current::segmentation;

use super::irq;
use super::process::VSpace;
use crate::memory::{PAddr, PhysicalMemoryAllocator};


unsafe fn get_kcb<'a>() -> ptr::NonNull<RefCell<Kcb>> {
    let kcb = segmentation::rdfsbase() as *mut RefCell<Kcb>;
    assert!(kcb != ptr::null_mut());

    ptr::NonNull::new_unchecked(kcb)
}

unsafe fn set_kcb(kcb: ptr::NonNull<RefCell<Kcb>>) {
    segmentation::wrfsbase(kcb.as_ptr() as u64);
}

pub struct Kcb {
    apic: apic::xapic::XAPIC,
    multiboot: Multiboot<'static>,
    kernel_binary: &'static [u8],
    init_vspace: VSpace<'static>,
    //fmanager: PhysicalMemoryAllocator,
}

impl Kcb {
    fn new(
        multiboot: Multiboot<'static>,
        apic: apic::xapic::XAPIC,
        kernel_binary: &'static [u8],
        init_vspace: VSpace<'static>, //fmanager: PhysicalMemoryAllocator
    ) -> Kcb {
        Kcb {
            multiboot: multiboot,
            apic: apic,
            kernel_binary: kernel_binary,
            init_vspace: init_vspace,
            //fmanager: fmanager,
        }
    }
}

pub(crate) fn init_kcb(
    multiboot: Multiboot<'static>,
    apic: apic::xapic::XAPIC,
    kernel_binary: &'static [u8],
    init_vspace: VSpace<'static>, //fmanager: PhysicalMemoryAllocator
) {
    let kcb: Box<RefCell<Kcb>> = Box::new(RefCell::new(Kcb::new(
        multiboot,
        apic,
        kernel_binary,
        init_vspace,
    )));

    let nptr: ptr::NonNull<RefCell<Kcb>> = Box::into_raw_non_null(kcb);
    unsafe { set_kcb(nptr) };
}

/// Execute closure `f` on the LKCB.
pub fn on_kcb<F, R>(f: F) -> R
where
    F: FnOnce(RefMut<Kcb>) -> R,
{
    irq::disable();
    let kcb_ptr: ptr::NonNull<RefCell<Kcb>> = unsafe { get_kcb() };
    let kcb_rc: &RefCell<Kcb> = unsafe { kcb_ptr.as_ref() };

    let r = { f(kcb_rc.borrow_mut()) };

    irq::enable();
    r
}
