// LKCB is the local kernel control that stores all core local state.

use core::borrow::BorrowMut;
use core::cell::{RefCell, RefMut};
use core::ptr;

use crate::memory::{tcache::TCache, GlobalMemory, PhysicalPageProvider};

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
    pmanager: Option<RefCell<TCache>>,
    pub gmanager: Option<&'static GlobalMemory>,
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,
    pub node: topology::NodeId,
}

impl Kcb {
    pub fn new(gmanager: &'static GlobalMemory, pmanager: TCache) -> Kcb {
        Kcb {
            gmanager: Some(gmanager),
            pmanager: Some(RefCell::new(pmanager)),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
            node: 0,
        }
    }

    pub fn pmanager(&self) -> RefMut<TCache> {
        self.pmanager.as_ref().unwrap().borrow_mut()
    }

    /// Returns a reference to the physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<TCache> {
        self.pmanager()
    }

    pub fn try_mem_manager(&self) -> Result<RefMut<TCache>, core::cell::BorrowMutError> {
        self.pmanager.as_ref().unwrap().try_borrow_mut()
    }
}

pub(crate) fn init_kcb(kptr: ptr::NonNull<Kcb>) {
    unsafe { set_kcb(kptr) };
}
