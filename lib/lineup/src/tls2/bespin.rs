// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::alloc::Layout;

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
pub fn get_tls_info() -> (&'static [u8], Layout) {
    let pinfo: kpi::process::ProcessInfo =
        kpi::syscalls::Process::process_info().expect("Can't get pinfo?");
    if pinfo.has_tls {
        let _bss_size = pinfo.tls_len_total - pinfo.tls_data_len;
        unsafe {
            // Safe: We know this exists because our ELF loader put TLS there (hopefully)
            (
                core::slice::from_raw_parts(
                    pinfo.tls_data as *const u8,
                    pinfo.tls_data_len as usize,
                ),
                Layout::from_size_align_unchecked(
                    pinfo.tls_len_total as usize + core::mem::size_of::<ThreadControlBlock>(),
                    pinfo.alignment as usize,
                ),
            )
        }
    } else {
        (&[], Layout::new::<ThreadControlBlock>())
    }
}
