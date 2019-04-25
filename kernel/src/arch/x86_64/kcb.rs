// LKCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{RefCell, RefMut};
use core::ptr;

use multiboot::Multiboot;

use x86::current::segmentation;

use crate::memory::{PAddr, PhysicalMemoryAllocator};

use super::irq;

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
    //fmanager: PhysicalMemoryAllocator,
}

impl Kcb {
    fn new(
        multiboot: Multiboot<'static>,
        apic: apic::xapic::XAPIC,
        //fmanager: PhysicalMemoryAllocator,
    ) -> Kcb {
        Kcb {
            multiboot: multiboot,
            apic: apic,
            //fmanager: fmanager,
        }
    }
}

pub(crate) fn init_kcb(
    multiboot: Multiboot<'static>,
    apic: apic::xapic::XAPIC,
    //fmanager: PhysicalMemoryAllocator,
) {
    let kcb: Box<RefCell<Kcb>> = Box::new(RefCell::new(Kcb::new(multiboot, apic)));

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
