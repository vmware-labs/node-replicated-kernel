// LKCB is the local kernel control that stores all core local state.

use core::cell::{RefCell, RefMut};
use core::ptr;

use crate::memory::buddy::BuddyFrameAllocator;
use crate::memory::PhysicalAllocator;

static mut KCB: *mut Kcb = ptr::null_mut();

pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb> {
    unsafe {
        if !KCB.is_null() {
            Some(&mut *KCB as &mut Kcb)
        } else {
            None
        }
    }
}

pub fn get_kcb<'a>() -> &'a mut Kcb {
    unsafe { &mut *KCB as &mut Kcb }
}

unsafe fn set_kcb(kcb: ptr::NonNull<Kcb>) {
    KCB = kcb.as_ptr();
}

pub struct Kcb {
    pmanager: RefCell<BuddyFrameAllocator>,
}

impl Kcb {
    pub fn new(pmanager: BuddyFrameAllocator) -> Kcb {
        Kcb {
            pmanager: RefCell::new(pmanager),
        }
    }

    pub fn pmanager(&self) -> RefMut<BuddyFrameAllocator> {
        self.pmanager.borrow_mut()
    }

    /// Returns a reference to the physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<dyn PhysicalAllocator> {
        self.pmanager()
    }
}

pub(crate) fn init_kcb(mut kcb: Kcb) {
    let kptr: ptr::NonNull<Kcb> = ptr::NonNull::from(&mut kcb);
    unsafe { set_kcb(kptr) };
}
