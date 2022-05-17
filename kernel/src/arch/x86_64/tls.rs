use alloc::alloc::Layout;
use core::mem;
use core::ptr;

pub fn get_tls_info() -> (&'static [u8], Layout) {
    (&[], Layout::new::<ThreadControlBlock>())
}

/// Per thread state of the scheduler.
///
/// This is what the `fs` register points to.
///
/// The thread-local-storage region is allocated
/// in front of that structure (since we do TLS variant 2).
///
/// The first three arguments essentially mirror the rump/NetBSD
/// `tls_tcb` struct for compatibility with NetBSD libpthread.
///
/// This struct is `repr(C)` because we depend on the order
/// of the first three elements.
#[repr(C, align(8))]
pub struct ThreadControlBlock {
    /// Points to self (this makes sure mov %fs:0x0 works because it will look
    /// up the pointer here)
    tcb_myself: *mut ThreadControlBlock,
    /// Unused but needed for compatibility since we don't do dynamic linking.
    tcb_dtv: *const *const u8,

    /// Some silly variable
    pub some_var: u64,
}

impl ThreadControlBlock {
    /// Creates a new thread local storage area.
    ///
    /// # Safety
    /// Does a bunch of unsafe memory operations to lay out the TLS area.
    ///
    /// Someone else also need to ensure that the allocated memory is `freed` at
    /// some point again.
    pub unsafe fn new_tls_area() -> *mut ThreadControlBlock {
        let ts_template = ThreadControlBlock {
            tcb_myself: ptr::null_mut(),
            tcb_dtv: ptr::null(),
            some_var: 0xdad,
        };

        let (initial_tdata, tls_layout) = get_tls_info();

        // Allocate memory for a TLS block: variant 2: [tdata, tbss, TCB], and
        // start of TCB goes in fs)
        let tls_base: *mut u8 = alloc::alloc::alloc_zeroed(tls_layout);

        // TODO(correctness): This doesn't really respect alignment of ThreadControlBlock :(
        // since we align to the TLS alignment requirements by ELF
        let tcb = tls_base.add(tls_layout.size() - mem::size_of::<ThreadControlBlock>());
        *(tcb as *mut ThreadControlBlock) = ts_template;
        (*(tcb as *mut ThreadControlBlock)).tcb_myself = tcb as *mut ThreadControlBlock;

        log::trace!(
            "new_tls_area: initial_tdata {:p} tls_layout {:?} tcb: {:p} myself: {:p}",
            initial_tdata,
            tls_layout,
            tcb,
            (*(tcb as *mut ThreadControlBlock)).tcb_myself
        );

        // Copy data
        tls_base.copy_from_nonoverlapping(initial_tdata.as_ptr(), initial_tdata.len());

        tcb as *mut ThreadControlBlock
    }
}
