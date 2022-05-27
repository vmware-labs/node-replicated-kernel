// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kernel TLS variant 2 implementation (for static linking only). Ensures
//! #[thread_local] stuff works after we call `ThreadControlBlock::init()`.

use alloc::alloc::Layout;
use core::mem;
use core::ptr;

use bootloader_shared::TlsInfo;
use log::trace;
use x86::bits64::segmentation;

use crate::error::{KError, KResult};

fn get_tls_region(info: &TlsInfo) -> (&'static [u8], Layout) {
    let tls_layout = Layout::from_size_align(info.tls_len_total as usize, info.alignment as usize)
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
    assert!(info.tls_data_len < isize::MAX.try_into().unwrap());
    let tls_region = unsafe {
        core::slice::from_raw_parts(info.tls_data as *const u8, info.tls_data_len as usize)
    };

    (tls_region, tls_layout)
}

/// Per-core TLS state in the kernel.
///
/// - This is what the `fs` register ends up pointing to. Ideally, we could tell
///   rustc to use the `gs` register for eventual perf. benefits, but currently
///   this isn't supported (see also
///   https://github.com/rust-lang/rust/issues/29594#issuecomment-843934159).
///
///
/// - The thread-local-storage variables are stored *in front* of that structure
/// (TLS variant 2 layout).
///
/// - This struct is `repr(C)` because TLS spec depends on the order of the
/// first two elements.
#[repr(C)]
pub(crate) struct ThreadControlBlock {
    /// Points to `self` (makes sure mov %fs:0x0 works)
    ///
    /// This is how the compiler looks up TLS things.
    tcb_myself: *mut ThreadControlBlock,

    /// For dynamic loading (unused but added for future compatibility (we don't
    /// do dynamic linking/modules)).
    tcb_dtv: *const *const u8,
}

impl ThreadControlBlock {
    /// Initialize TLS for the current core.
    ///
    /// # Returns
    /// The memory location that `fs` points to. This is used by the kernel to
    /// restore the register to the correct kernel value on entry.
    ///
    /// # Safety
    /// - `enable_fsgsbase` has already been called on the core (sets bit in
    ///   Cr4)
    /// - Assume that BIOS/UEFI initializes fs with 0x0
    pub(super) unsafe fn init(info: &TlsInfo) -> KResult<*const ThreadControlBlock> {
        let tcb = ThreadControlBlock::new(info);
        if segmentation::rdfsbase() == 0x0 {
            ThreadControlBlock::install(tcb);
            Ok(tcb)
        } else {
            Err(KError::TLSAlreadyInitialized)
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
    fn new(info: &TlsInfo) -> *const ThreadControlBlock {
        const TCB_INITIAL: ThreadControlBlock = ThreadControlBlock {
            tcb_myself: ptr::null_mut(),
            tcb_dtv: ptr::null(),
        };

        let (initial_tdata, tls_data_layout) = get_tls_region(info);

        // Allocate memory for a TLS block: variant 2: [tdata, tbss, TCB], and
        // start of TCB goes in fs):

        // Safety `alloc_zeroed`:
        let (tls_all_layout, _offset) = tls_data_layout
            .extend(Layout::new::<ThreadControlBlock>())
            .expect("Can't append ThreadControlBlock to TLS layout during init");
        // Make sure `extend` didn't end up padding for `ThreadControlBlock` (so
        // tdata/tbss is still properly aligned on access): If not (I think) we
        // might lose alignment of `tls_data_layout` because we start from the
        // TCB going backwards. The ELF Handling For TLS by Drepper
        // unfortunately does not talk a lot about alignment. But it seems to
        // assume that ThreadControlBlock is allocated by `malloc` (hence 16
        // byte aligned?).
        assert!(
            tls_all_layout.size() == mem::size_of::<ThreadControlBlock>() + tls_data_layout.size(),
            "`extend` did not insert padding"
        );
        assert!(tls_data_layout.size() > 0, "allocate a non-zero size");

        let tls_base: *mut u8 = unsafe { alloc::alloc::alloc_zeroed(tls_all_layout) };
        assert_ne!(tls_base, ptr::null_mut(), "Out of memory during init?");

        unsafe {
            // Safety `add`:
            // - Start and result pointer must be in bounds or one byte past the end of the same object:
            assert!(tls_all_layout.size() >= mem::size_of::<ThreadControlBlock>());
            // - Compute offset (bytes can not overflow) isize: Yes, layout is
            //   valid, and we substract from it
            // - The offset being in bounds cannot rely on "wrapping around" the
            //   address space: Yes, trivial
            let tcb_start_addr =
                tls_base.add(tls_all_layout.size() - mem::size_of::<ThreadControlBlock>());

            // Safety deref+assignment:
            // - We know location is valid and aligned because of all the work above
            // - No mutable outside of this function
            let tcb = tcb_start_addr as *mut ThreadControlBlock;
            // - Copy of plain-old-data, raw-pointer
            *tcb = TCB_INITIAL;
            // Safety: TLS lookups on x86 will be using `fs:0x0` so we have add
            // a self-pointer as the first arg of the TCB
            (*tcb).tcb_myself = tcb;

            trace!(
                "initial_tdata {:?} len={}, tls_base = {:?} tcb = {:?}",
                initial_tdata,
                initial_tdata.len(),
                tls_base,
                tcb
            );

            // Initialize tdata section with template data from ELF:
            // Safety `copy_from_nonoverlapping`:
            // - src must be valid for reads of count * size_of::<T>() bytes: Yes (see allocation above)
            // - dst must be valid for writes of count * size_of::<T>() bytes: Yes (see allocation above)
            // - Both src and dst must be properly aligned: Yes (see allocation above)
            // - No overlap: Yes (assuming allocator/ELF parsing is correct)
            tls_base.copy_from_nonoverlapping(initial_tdata.as_ptr(), initial_tdata.len());

            tcb as *const ThreadControlBlock
        }
    }

    /// Installs a ThreadControBlock in the `fs` register of the current core.
    ///
    /// # Safety
    ///
    /// - This will set the memory for all `#[thread_local]` variables and
    ///   should *only* be called during init when setting up TLS.
    ///
    /// - Assumes that `ptr` has been correctly allocated and initialized (with
    ///   [`ThreadControlBlock::new`]) and `ptr` is only used by one core.
    ///
    /// - The same `ptr` also needs to be restored/saved upon entering/exiting
    ///   from syscalls/interrupt. This is not necessarily a safety concern for
    ///   this function (as long as we don't change `ptr` after init (and we
    ///   shouldn't)). `fs` save/restore is handled in the assembly code for
    ///   syscalls/interrupts.
    unsafe fn install(ptr: *const ThreadControlBlock) {
        segmentation::wrfsbase(ptr as u64)
    }
}
