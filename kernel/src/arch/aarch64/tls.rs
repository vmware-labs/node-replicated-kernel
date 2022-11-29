// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kernel TLS variant 2 implementation (for static linking only). Ensures
//! #[thread_local] stuff works after we call `ThreadControlBlock::init()`.

use alloc::alloc::Layout;
use core::mem;
use core::ptr;

use bootloader_shared::TlsInfo;
use kpi::KERNEL_BASE;

use cortex_a::{asm::barrier, registers::*};
use tock_registers::interfaces::{Readable, Writeable};

use crate::arch::kcb::{get_kcb, try_get_kcb, AArch64Kcb};
use crate::error::{KError, KResult};

// Allocate memory for a TLS block:
// *------------------------------------------------------------------------------*
// | KCB    | tcb | X | tls1 | ... | tlsN | ... | tls_cnt | dtv[1] | ... | dtv[N] |
// *------------------------------------------------------------------------------*
// ^         ^         ^             ^            ^
// td        tp      dtv[1]       dtv[n+1]       dtv

pub(super) fn get_tls_layout() -> Layout {
    if let Some(tls_args) = crate::KERNEL_ARGS.get().and_then(|k| k.tls_info.as_ref()) {
        Layout::from_size_align(tls_args.tls_len_total as usize, tls_args.alignment as usize)
            .expect("TLS size / alignment issue during init?")
    } else {
        Layout::from_size_align(0, 16).unwrap()
    }
}

fn get_tls_region() -> (&'static [u8], Layout) {
    if let Some(tls_args) = crate::KERNEL_ARGS.get().and_then(|k| k.tls_info.as_ref()) {
        let tls_layout =
            Layout::from_size_align(tls_args.tls_len_total as usize, tls_args.alignment as usize)
                .expect("TLS size / alignment issue during init?");

        // Safety `from_raw_parts`:
        // - We know this exists/is valid because our ELF loader put the TLS section
        //   there (hopefully)
        // - memory range of this slice must be contained within a single allocate
        //   object: static blob, put there by the ELF loader, no deallocation
        // - Alignment is `1` for u8 slices:
        static_assertions::const_assert!(mem::align_of::<[u8; 1]>() == 1);
        // - Properly initialized values: It's plain-old-data
        // - total size len * mem::size_of::<T>() of the slice must be no larger than isize::MAX:
        assert!(tls_args.tls_data_len < isize::MAX.try_into().unwrap());
        let tls_region = unsafe {
            core::slice::from_raw_parts(
                tls_args.tls_data as *const u8,
                tls_args.tls_data_len as usize,
            )
        };
        (tls_region, tls_layout)
    } else {
        (&[], Layout::from_size_align(0, 16).unwrap())
    }
}

/// Per-core TLS state in the kernel.
///
/// - This struct is `repr(C)` because TLS spec depends on the order of the
/// first two elements.
#[repr(C, align(16))]
pub(crate) struct ThreadControlBlock {
    /// For dynamic loading (unused but added for future compatibility (we don't
    /// do dynamic linking/modules)).
    tcb_dtv: *const *const u8,
    _pad: *const *const u8,
}

impl ThreadControlBlock {
    pub fn init_tls(&mut self) {
        let (initial_tdata, tls_data_layout) = get_tls_region();

        log::info!("tcb vaddr: {:p}", self);

        // Allocate memory for a TLS block:
        // *------------------------------------------------------------------------------*
        // | KCB    | tcb | X | tls1 | ... | tlsN | ... | tls_cnt | dtv[1] | ... | dtv[N] |
        // *------------------------------------------------------------------------------*
        // ^         ^         ^             ^            ^
        // td        tp      dtv[1]       dtv[n+1]       dtv

        let tp: *mut ThreadControlBlock = self as *mut ThreadControlBlock;

        assert_eq!(((tp as u64) & 0x7), 0, "Alignment!");

        log::trace!(
            "initial_tdata {:?} len={}, tls_base = {:?} tcb = {:p}",
            initial_tdata,
            initial_tdata.len(),
            tp,
            self
        );

        log::info!(
            "core::mem::size_of::<ThreadControlBlock>() {:?}",
            core::mem::size_of::<ThreadControlBlock>()
        );

        // Initialize tdata section with template data from ELF:
        // Safety `copy_from_nonoverlapping`:
        // - src must be valid for reads of count * size_of::<T>() bytes: Yes (see allocation above)
        // - dst must be valid for writes of count * size_of::<T>() bytes: Yes (see allocation above)
        // - Both src and dst must be properly aligned: Yes (see allocation above)
        // - No overlap: Yes (assuming allocator/ELF parsing is correct)
        let tdata: *mut u8 =
            ((tp as usize) + (core::mem::size_of::<ThreadControlBlock>())) as *mut u8;

        unsafe {
            tdata.copy_from_nonoverlapping(initial_tdata.as_ptr(), initial_tdata.len());
        }

        self.tcb_dtv = tdata as *const *const u8;
    }

    pub const fn new() -> ThreadControlBlock {
        ThreadControlBlock {
            tcb_dtv: ptr::null(),
            _pad: ptr::null(),
        }
    }

    /// Creates a new thread local storage area.
    ///
    /// Note that the returned pointer points somewhere in the middle/end of the
    /// allocated memory region as the TLS variant 2 layout says the
    /// thread-local data comes *before* the TLS control block.
    ///
    /// # Notes
    ///
    /// Does a bunch of unsafe memory operations to lay out the TLS area.
    ///
    /// Currently leaks the memory, someone else needs to ensure that the
    /// allocated memory is `freed` at some point again if we ever shutdown
    /// cores.
    pub(super) fn with_tls_info(info: &TlsInfo) -> *const ThreadControlBlock {
        let (initial_tdata, tls_data_layout) = get_tls_region();

        // Allocate memory for a TLS block:
        // *------------------------------------------------------------------------------*
        // | KCB    | tcb | X | tls1 | ... | tlsN | ... | tls_cnt | dtv[1] | ... | dtv[N] |
        // *------------------------------------------------------------------------------*
        // ^         ^         ^             ^            ^
        // td        tp      dtv[1]       dtv[n+1]       dtv

        // Safety `alloc_zeroed`:
        // we extend this by the KCB size, so we can store the KCB in front.
        let (tls_all_layout, _offset) = tls_data_layout
            .extend(Layout::new::<AArch64Kcb>())
            .expect("Can't append ThreadControlBlock to TLS layout during init");

        // Make sure `extend` didn't end up padding for `ThreadControlBlock` (so
        // tdata/tbss is still properly aligned on access): If not (I think) we
        // might lose alignment of `tls_data_layout` because we start from the
        // TCB going backwards. The ELF Handling For TLS by Drepper
        // unfortunately does not talk a lot about alignment. But it seems to
        // assume that ThreadControlBlock is allocated by `malloc` (hence 16
        // byte aligned?).
        assert!(
            tls_all_layout.size() == mem::size_of::<AArch64Kcb>() + tls_data_layout.size(),
            "`extend` did not insert padding"
        );
        assert!(tls_data_layout.size() > 0, "allocate a non-zero size");

        // the base pointer of the tls block pointing to the KCB
        let td: *mut u8 = unsafe { alloc::alloc::alloc_zeroed(tls_all_layout) };
        assert_ne!(td, ptr::null_mut(), "Out of memory during init?");

        // tp is the TCB in the KCB.
        let tp: *mut ThreadControlBlock =
            (td as u64 + memoffset::offset_of!(AArch64Kcb, tcb) as u64) as *mut ThreadControlBlock;
        assert_eq!(((tp as u64) & 0x7), 0, "Alignment!");

        unsafe {
            // Safety `add`:
            // - Start and result pointer must be in bounds or one byte past the end of the same object:
            assert!(tls_all_layout.size() >= mem::size_of::<AArch64Kcb>());
            // - Compute offset (bytes can not overflow) isize: Yes, layout is
            //   valid, and we substract from it
            // - The offset being in bounds cannot rely on "wrapping around" the
            //   address space: Yes, trivial

            // Safety deref+assignment:
            // - We know location is valid and aligned because of all the work above
            // - No mutable outside of this function
            let tcb = tp as *mut ThreadControlBlock;

            // - Copy of plain-old-data, raw-pointer
            *tcb = ThreadControlBlock::new();

            log::trace!(
                "initial_tdata {:?} len={}, tls_base = {:?} tcb = {:?}",
                initial_tdata,
                initial_tdata.len(),
                tp,
                tcb
            );

            // Initialize tdata section with template data from ELF:
            // Safety `copy_from_nonoverlapping`:
            // - src must be valid for reads of count * size_of::<T>() bytes: Yes (see allocation above)
            // - dst must be valid for writes of count * size_of::<T>() bytes: Yes (see allocation above)
            // - Both src and dst must be properly aligned: Yes (see allocation above)
            // - No overlap: Yes (assuming allocator/ELF parsing is correct)
            let tdata: *mut u8 =
                ((tp as usize) + (core::mem::size_of::<ThreadControlBlock>())) as *mut u8;

            tdata.copy_from_nonoverlapping(initial_tdata.as_ptr(), initial_tdata.len());

            (*tcb).tcb_dtv = tdata as *const *const u8;

            tcb as *const ThreadControlBlock
        }
    }

    pub(crate) fn try_get_tcb<'a>() -> Option<&'a mut ThreadControlBlock> {
        let kcb = try_get_kcb()?;
        Some(&mut kcb.tcb)
        // unsafe {
        //     // Safety:
        //     // - TODO(safety+soundness): not safe, should return a non-mut reference
        //     //   with mutable stuff (it's just save_area that's left) wrapped in
        //     //   RefCell or similar (treat the same as a thread-local)
        //     let kcb_raw = TPIDR_EL1.get();
        //     if kcb_raw != 0 {
        //         Some(ThreadControlBlock::get_tcb())
        //     } else {
        //         None
        //     }
        // }
    }

    fn get_tcb<'a>() -> &'a mut ThreadControlBlock {
        let kcb = get_kcb();
        &mut kcb.tcb

        // unsafe {
        //     let tcb_raw = TPIDR_EL1.get();
        //     let tcb = tcb_raw as *mut ThreadControlBlock;

        //     assert!(tcb != ptr::null_mut(), "TCB not found in gs register.");
        //     let kptr = ptr::NonNull::new_unchecked(tcb);
        //     &mut *kptr.as_ptr()
        // }
    }
}
