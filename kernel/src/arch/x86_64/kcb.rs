// KCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{Ref, RefCell, RefMut};
use core::ptr;

use x86::current::segmentation;

use apic::xapic::XAPIC;

use super::irq;
use super::vspace::VSpace;

use crate::arch::{KernelArgs, Module};
use crate::memory::buddy::BuddyFrameAllocator;
use crate::memory::{PAddr, PhysicalMemoryAllocator};

pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb> {
    unsafe {
        let kcb = segmentation::rdfsbase() as *mut Kcb;
        if kcb != ptr::null_mut() {
            let kptr = ptr::NonNull::new_unchecked(kcb);
            Some(&mut *kptr.as_ptr())
        } else {
            None
        }
    }
}

pub fn get_kcb<'a>() -> &'a mut Kcb {
    unsafe {
        let kcb = segmentation::rdfsbase() as *mut Kcb;
        assert!(kcb != ptr::null_mut());
        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

unsafe fn set_kcb(kcb: ptr::NonNull<Kcb>) {
    segmentation::wrfsbase(kcb.as_ptr() as u64);
}

pub struct Kcb {
    kernel_args: RefCell<&'static KernelArgs<[Module; 2]>>,
    kernel_binary: RefCell<&'static [u8]>,
    init_vspace: RefCell<VSpace<'static>>,
    pmanager: RefCell<BuddyFrameAllocator>,
    apic: RefCell<XAPIC>,
}

impl Kcb {
    pub fn new(
        kernel_args: &'static KernelArgs<[Module; 2]>,
        kernel_binary: &'static [u8],
        init_vspace: VSpace<'static>,
        pmanager: BuddyFrameAllocator,
        apic: XAPIC,
    ) -> Kcb {
        Kcb {
            kernel_args: RefCell::new(kernel_args),
            kernel_binary: RefCell::new(kernel_binary),
            init_vspace: RefCell::new(init_vspace),
            pmanager: RefCell::new(pmanager),
            apic: RefCell::new(apic),
        }
    }

    pub fn pmanager(&self) -> RefMut<BuddyFrameAllocator> {
        self.pmanager.borrow_mut()
    }

    pub fn apic(&self) -> RefMut<XAPIC> {
        self.apic.borrow_mut()
    }

    pub fn init_vspace(&self) -> RefMut<VSpace<'static>> {
        self.init_vspace.borrow_mut()
    }

    pub fn kernel_binary(&self) -> Ref<&'static [u8]> {
        self.kernel_binary.borrow()
    }

    pub fn kernel_args(&self) -> Ref<&'static KernelArgs<[Module; 2]>> {
        self.kernel_args.borrow()
    }
}

pub(crate) fn init_kcb(mut kcb: Kcb) {
    let kptr: ptr::NonNull<Kcb> = ptr::NonNull::from(&mut kcb);
    unsafe { set_kcb(kptr) };
}
/*

// Execute closure `f` on the LKCB.
pub fn on_kcb<F, R>(f: F) -> R
where
    F: FnOnce(RefMut<Kcb>) -> R,
{
    irq::disable();
    let kcb_ptr: ptr::NonNull<Kcb> = unsafe { get_kcb() };
    let kcb_rc: &RefCell<Kcb> = unsafe { kcb_ptr.as_ref() };

    let r = { f(kcb_rc.borrow_mut()) };

    irq::enable();
    r
}
*/
