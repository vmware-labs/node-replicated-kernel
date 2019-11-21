//! KCB is the local kernel control that stores all core local state.
use core::cell::{RefCell, RefMut};
use core::ptr;

use crate::arch::vspace::VSpace;
use crate::kcb::Kcb;
use crate::memory::{tcache::TCache, GlobalMemory};

use slabmalloc::ZoneAllocator;

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

/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb(kcb: &mut Kcb) {
    let kptr: ptr::NonNull<Kcb> = ptr::NonNull::from(kcb);
    unsafe { set_kcb(kptr) };
}

pub struct ArchKcb {}

impl ArchKcb {
    pub(crate) fn install(&mut self) {}
}
