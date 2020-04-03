use core::{mem, ptr};
use core::alloc::Layout;

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

pub(crate) unsafe fn set_scb(scb: *const SchedulerControlBlock) {
    segmentation::wrgsbase(scb as *const _ as u64)
}

/// Determines the necessary space for per-thread TLS memory region.
///
/// Total required bytes is the sum of the `tdata`, `tbss`,
/// and a statically defined extra section.
/// (i.e., the sum of all return values)
pub fn calculate_tls_size() -> (&'static [u8], Layout) {
    let pinfo: kpi::process::ProcessInfo = kpi::syscalls::process_info().expect("Can't get pinfo?");

    info!(
        "TLS data + bss = {}",
        pinfo.tls_len_total
    );
    info!("alignment of ThreadControlBlock = {:?}", core::alloc::Layout::new::<ThreadControlBlock>());
    if pinfo.has_tls {
        let bss_size = pinfo.tls_len_total - pinfo.tls_data_len;

        unsafe {
            // Safe: We know this exists because our ELF loader put TLS there (hopefully)
            (core::slice::from_raw_parts(pinfo.tls_data as *const u8, pinfo.tls_data_len as usize),
            Layout::from_size_align_unchecked(pinfo.tls_len_total as usize + core::mem::size_of::<ThreadControlBlock>(), pinfo.alignment as usize))
        }
    }
    else {
        (&[], Layout::new::<ThreadControlBlock>())
    }
}


pub fn calculate_tls_size2() -> (&'static [u8], Layout) {
    /// ELF TLS sections start and ends
    extern "C" {
        static _tdata_start: u8;
        static _tdata_end: u8;
        static _tbss_start: u8;
        static _tbss_end: u8;
    }

    unsafe {
        let tdata_start_ptr = &_tdata_start as *const u8;
        let tdata_end_ptr = &_tdata_end as *const u8;
        let tbss_start_ptr = &_tbss_start as *const u8;
        let tbss_end_ptr = &_tbss_end as *const u8;

        let tdata_len = tdata_start_ptr.offset_from(tdata_end_ptr) as usize;
        let tbss_len = tbss_start_ptr.offset_from(tbss_end_ptr) as usize;

        // Safe: We know this exists because our ELF loader put TLS there (hopefully)
        (core::slice::from_raw_parts(tdata_start_ptr as *const u8, tdata_len),
        Layout::from_size_align_unchecked(tdata_len + tbss_len + core::mem::size_of::<ThreadControlBlock>(), 8))
    }
}

