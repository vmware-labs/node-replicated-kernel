use core::{mem, ptr};

use log::info;
use x86::bits64::segmentation;

use super::{SchedulerControlBlock, ThreadControlBlock};

pub(crate) unsafe fn get_tcb<'a>() -> *mut ThreadControlBlock<'a> {
    segmentation::rdfsbase() as *mut ThreadControlBlock
}

pub(crate) unsafe fn set_tcb(t: *mut ThreadControlBlock) {
    segmentation::wrfsbase(t as u64)
}

pub(crate) unsafe fn get_scb() -> *const SchedulerControlBlock {
    segmentation::rdgsbase() as *const SchedulerControlBlock
}

pub(crate) unsafe fn set_scb(t: &'static SchedulerControlBlock) {
    segmentation::wrgsbase(t as *const _ as u64)
}

/// Determines the necessary space for per-thread TLS memory region.
///
/// Total required bytes is the sum of the `tdata`, `tbss`,
/// and a statically defined extra section.
/// (i.e., the sum of all return values)
pub fn calculate_tls_size() -> (usize, usize, usize) {
    /// ELF TLS sections start and ends
    ///
    /// The linker better inserts these symbols for us.
    extern "C" {
        static _tdata_start: u8;
        static _tdata_end: u8;
        static _tbss_start: u8;
        static _tbss_end: u8;
    }

    let (tdata_size, tbss_size) = unsafe {
        let tdata_start_ptr = &_tdata_start as *const u8;
        let tdata_end_ptr = &_tdata_end as *const u8;
        let tbss_start_ptr = &_tbss_start as *const u8;
        let tbss_end_ptr = &_tbss_end as *const u8;

        (
            tdata_start_ptr.offset_from(tdata_end_ptr),
            tbss_start_ptr.offset_from(tbss_end_ptr),
        )
    };

    let tcb_size = mem::size_of::<ThreadControlBlock>();

    info!(
        "tls area size is: data + bss + extra = {}",
        tdata_size + tbss_size + tcb_size as isize
    );
    (tdata_size as usize, tbss_size as usize, tcb_size)
}
