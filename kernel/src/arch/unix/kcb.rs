// LKCB is the local kernel control that stores all core local state.

use core::cell::{RefCell, RefMut};
use core::ptr;

use crate::memory::{tcache::TCache, PhysicalPageProvider};

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

pub struct Kcb {
    pmanager: RefCell<TCache>,
    /// A handle to the per-core ZoneAllocator
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,
}

impl Kcb {
    pub fn new(pmanager: TCache) -> Kcb {
        Kcb {
            pmanager: RefCell::new(pmanager),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }

    pub fn pmanager(&self) -> RefMut<dyn PhysicalPageProvider> {
        self.pmanager.borrow_mut()
    }

    /// Returns a reference to the physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<dyn PhysicalPageProvider> {
        self.pmanager()
    }
}

pub(crate) fn init_kcb(kptr: ptr::NonNull<Kcb>) {
    unsafe { set_kcb(kptr) };
}
