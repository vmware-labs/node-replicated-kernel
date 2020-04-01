//! A silly implementation of get/set tcb/scb on unix
//!
//! Super meta since we use posix/thread_local to
//! implement it.
use core::cell::Cell;
use core::{mem, ptr};

use super::{SchedulerControlBlock, ThreadControlBlock};

#[thread_local]
pub static TCB: Cell<*mut ThreadControlBlock> = Cell::new(ptr::null_mut());

#[thread_local]
pub static SCB: Cell<*const SchedulerControlBlock> = Cell::new(ptr::null());

pub(crate) unsafe fn get_tcb<'a>() -> *mut ThreadControlBlock<'a> {
    mem::transmute::<*mut ThreadControlBlock<'static>, *mut ThreadControlBlock<'a>>(TCB.get())
}

pub(crate) unsafe fn set_tcb<'a>(tcb: *mut ThreadControlBlock<'a>) {
    TCB.set(mem::transmute::<
        *mut ThreadControlBlock<'a>,
        *mut ThreadControlBlock<'static>,
    >(tcb));
}

pub(crate) unsafe fn get_scb() -> *const SchedulerControlBlock {
    SCB.get()
}

pub(crate) unsafe fn set_scb(scb: *const SchedulerControlBlock) {
    SCB.set(scb);
}

/// A poor way to estimate the TLS size on unix.
#[cfg(target_family = "unix")]
pub fn calculate_tls_size() -> (usize, usize, usize) {
    // We only use this for tests, so we just estimate our TLS size...
    // Ideally we parse the ELF of our process to determine the static TLS size
    (2048, 1024, mem::size_of::<ThreadControlBlock>())
}
