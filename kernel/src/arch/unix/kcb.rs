//! KCB is the local kernel control that stores all core local state.
use alloc::boxed::Box;
use core::cell::{RefCell, RefMut};
use core::pin::Pin;
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

#[repr(C)]
pub struct ArchKcb {
    /// Pointer to the syscall stack (this is referenced in assembly early on in exec.S)
    /// and should therefore always be at offset 0 of the Kcb struct!
    pub(crate) syscall_stack_top: *mut u8,

    /// Pointer to the save area of the core,
    /// this is referenced on trap/syscall entries to save the CPU state into it.
    ///
    /// State from the save_area may be copied into current_process` save area
    /// to handle upcalls (in the general state it is stored/resumed from here).
    pub save_area: Option<Pin<Box<kpi::arch::SaveArea>>>,
}

impl Default for ArchKcb {
    fn default() -> ArchKcb {
        ArchKcb {
            syscall_stack_top: ptr::null_mut(),
            save_area: None,
        }
    }
}

impl ArchKcb {
    pub(crate) fn install(&mut self) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem::{self, MaybeUninit};

    #[test]
    fn save_area_offset() {
        let kcb: ArchKcb = unsafe { MaybeUninit::zeroed().assume_init() };
        assert_eq!(
            (&kcb.save_area as *const _ as usize) - (&kcb as *const _ as usize),
            8,
            "The save_area entry should be at offset 8 of KCB (for assembly)"
        );
    }
}
