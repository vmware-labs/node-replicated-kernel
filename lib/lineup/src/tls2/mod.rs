// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An implementation of TLS variant 2 (but we currently support only static linking)
//!
//! This is a pretty simple case:
//!
//! 1. We determine the TLS size (by computing offset from linker section symbols)
//!    (we could also do this by parsing the relevant ELF section)
//! 2. We allocate a block of memory which is TLS size from ELF + thread control block (TCB)
//! 3. We lay it out in memory such that TLS is before the TCB (this is variant 2)
//! 4. Need a way to program the 'fs' register to point to our TCB
//!
//! # Useful resources to understand TLS
//! The spec: https://www.uclibc.org/docs/tls.pdf
//! A random blog post: https://chao-tic.github.io/blog/2018/12/25/tls#introduction

use alloc::vec::Vec;

use core::ops::Add;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::{mem, ptr};

use fringe::generator::Yielder;

use crossbeam_queue::ArrayQueue;
use rawtime::{Duration, Instant};

use crate::stack::LineupStack;
use crate::threads::{ThreadId, YieldRequest, YieldResume};
use crate::upcalls::Upcalls;
use crate::{CoreId, IrqVector};

#[cfg(all(target_os = "nrk", target_arch = "x86_64"))]
pub mod nrk_x86_64;
#[cfg(all(target_os = "nrk", target_arch = "x86_64"))]
pub use crate::tls2::nrk_x86_64 as arch;

#[cfg(all(target_os = "nrk", target_arch = "aarch64"))]
pub mod nrk_aarch64;

#[cfg(all(target_os = "nrk", target_arch = "aarch64"))]
pub use crate::tls2::nrk_aarch64 as arch;

#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "unix")]
pub use crate::tls2::unix as arch;

use kpi::KERNEL_BASE;

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
/// ```C
/// struct tls_tcb {
///   void *tcb_self;  // 0
///   void **tcb_dtv;  // 8
///   void *tcb_pthread; // 16
/// };
/// ```
///
/// This struct is `repr(C)` because we depend on the order
/// of the first three elements.
#[repr(C)]
pub struct ThreadControlBlock<'a> {
    /// Points to self (this makes sure mov %fs:0x0 works
    /// because it will look up the pointer here)
    tcb_myself: *mut ThreadControlBlock<'a>,
    /// Unused but needed for compatibility since we don't do dynamic linking.
    tcb_dtv: *const *const u8,
    /// Used by libpthread (rump) to access pthread internal state.
    pub tcb_pthread: *mut u8,

    /// Our yielder for communicating to the scheduler.
    pub(crate) yielder: Option<&'a Yielder<YieldResume, YieldRequest>>,

    /// Thread ID.
    pub(crate) tid: ThreadId,

    /// Core affinity.
    pub current_core: CoreId,
    /// Contains upcalls (TODO: can't this be in SchedulerControlBlock?)
    pub upcalls: Upcalls,

    /// Stores pointer to lwp (TODO: figure this out can probably be thread local now)
    pub rump_lwp: AtomicPtr<u64>,
    /// Stores pointer to lwp (TODO: figure this out can probably be thread local now)
    pub rumprun_lwp: *const u64,

    /// The current errno variable (for libc compatibility).
    pub errno: i32,
}

impl<'a> ThreadControlBlock<'a> {
    /// Creates a new thread local storage area.
    ///
    /// # Safety
    /// Does a bunch of unsafe memory operations to lay out the TLS area.
    ///
    /// Someone else also need to ensure that the allocated memory is `freed` at
    /// some point again.
    pub unsafe fn new_tls_area() -> *mut ThreadControlBlock<'a> {
        let ts_template = ThreadControlBlock {
            tcb_myself: ptr::null_mut(),
            tcb_dtv: ptr::null(),
            tcb_pthread: ptr::null_mut(),
            yielder: None,
            tid: ThreadId(0),
            current_core: 0,
            errno: 0,
            upcalls: Default::default(),
            rump_lwp: AtomicPtr::new(ptr::null_mut()),
            rumprun_lwp: ptr::null_mut(),
        };

        let (initial_tdata, tls_layout) = arch::get_tls_info();

        // Allocate memory for a TLS block (variant 2: [tdata, tbss, TCB], and start of TCB goes in fs)
        let tls_base: *mut u8 = alloc::alloc::alloc_zeroed(tls_layout);

        // TODO(correctness): This doesn't really respect alignment of ThreadControlBlock :(
        // since we align to the TLS alignment requirements by ELF
        let tcb = tls_base.add(tls_layout.size() - mem::size_of::<ThreadControlBlock>());
        *(tcb as *mut ThreadControlBlock) = ts_template;
        // Initialize TCB self
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

    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder.unwrap()
    }

    pub fn set_lwp(&mut self, lwp_ptr: *mut u64) {
        self.rump_lwp.store(lwp_ptr, Ordering::SeqCst);
    }

    pub fn spawn_with_args(
        &self,
        s: LineupStack,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
        core_id: CoreId,
        irq_vector: Option<IrqVector>,
        tcb: *mut ThreadControlBlock<'static>,
    ) -> Option<ThreadId> {
        let request = YieldRequest::SpawnWithArgs(s, f, arg, core_id, irq_vector, tcb);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn spawn_on_core(
        &self,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
        core_id: CoreId,
    ) -> Option<ThreadId> {
        let request = YieldRequest::Spawn(f, arg, core_id, None);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn spawn_irq_thread(
        &self,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
        core_id: CoreId,
        irq_vector: IrqVector,
    ) -> Option<ThreadId> {
        let request = YieldRequest::Spawn(f, arg, core_id, Some(irq_vector));
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn spawn(
        &self,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
    ) -> Option<ThreadId> {
        let request = YieldRequest::Spawn(f, arg, self.current_core, None);
        match self.yielder().suspend(request) {
            YieldResume::Spawned(tid) => Some(tid),
            _ => None,
        }
    }

    pub fn sleep(&self, d: Duration) {
        let request = YieldRequest::Timeout(Instant::now().add(d));
        self.yielder().suspend(request);
    }

    pub fn block(&self) {
        let request = YieldRequest::Unrunnable(Environment::tid());
        self.yielder().suspend(request);
    }

    pub fn make_runnable(&self, tid: ThreadId) {
        let request = YieldRequest::Runnable(tid);
        self.yielder().suspend(request);
    }

    pub fn make_all_runnable(&self, tids: Vec<ThreadId>) {
        let request = YieldRequest::RunnableList(tids);
        self.yielder().suspend(request);
    }

    pub fn make_unrunnable(&self, tid: ThreadId) {
        let request = YieldRequest::Unrunnable(tid);
        self.yielder().suspend(request);
    }

    pub fn join(&self, tid: ThreadId) {
        let request = YieldRequest::JoinOn(tid);
        self.yielder().suspend(request);
    }

    pub(crate) fn suspend(&self, request: YieldRequest) {
        self.yielder().suspend(request);
    }

    pub fn relinquish(&self) {
        self.suspend(YieldRequest::None);
    }
}

/// This is global scheduler-state. Every thread (and also non-threaded upcall handlers)
/// can access this (ideally through the `gs` register).
///
/// It's separate from ThreadState since it has to be always there
/// (an IRQ/upcall may happen when the TCB/fs is not in a well defined state).
///
/// It's allocated and lives as part of the scheduler struct.
#[derive(Debug)]
pub struct SchedulerControlBlock {
    /// Used by an upcall handler to raise an IRQ.
    ///
    /// We can't just update the scheduler state directly because
    /// someone might hold a spinlock on the runlists while being interrupted.
    pub pending_irqs: ArrayQueue<u64>,

    /// Specific to a pointer of of upcall handlers set by the rumpkernel
    pub rump_upcalls: AtomicPtr<u64>,

    /// Core identifier of this scheduler state
    pub core_id: usize,
}

impl SchedulerControlBlock {
    /// Construct a scheduler state (no IRQ raised)
    /// and no upcall handler is set.
    pub fn new(core_id: CoreId) -> Self {
        SchedulerControlBlock {
            pending_irqs: ArrayQueue::new(4),
            rump_upcalls: AtomicPtr::new(ptr::null_mut()),
            core_id,
        }
    }
}

impl SchedulerControlBlock {
    /// Sets the control block for the scheduler.
    ///
    /// # Safety
    /// Ideally this should be called before other stuff relies on it being there.
    pub unsafe fn preinstall(&self) {
        arch::set_scb(self as *const SchedulerControlBlock);
    }
    /// Sets the upcall pointer for rumpkernel integration (we ignore the version)
    ///
    /// This is usually called at some point during `rump_init`.
    ///
    /// # Panics
    /// If called more than once.
    pub fn set_rump_context(&self, _version: i64, upcall_ptr: *mut u64) {
        let r = self.rump_upcalls.swap(upcall_ptr, Ordering::Relaxed);
        assert!(r.is_null());
        assert!(!self.rump_upcalls.load(Ordering::Relaxed).is_null());
    }
}

/// Convenience function to access the TCB or SCB structs.
pub struct Environment {}

impl Environment {
    #[cfg(target_os = "nrk")]
    pub fn tid() -> ThreadId {
        arch::tid()
    }

    #[cfg(target_family = "unix")]
    pub fn tid() -> ThreadId {
        unsafe {
            let tcb = arch::get_tcb() as *mut ThreadControlBlock;
            assert!(!tcb.is_null(), "Don't have TCB available?");
            (*tcb).tid
        }
    }

    // TODO(correctness): this needs some hardending to avoid aliasing of ThreadState!
    #[cfg(target_os = "nrk")]
    pub fn thread<'a>() -> &'a mut ThreadControlBlock<'static> {
        arch::thread()
    }

    #[cfg(target_family = "unix")]
    pub fn thread<'a>() -> &'a mut ThreadControlBlock<'static> {
        unsafe {
            let tcb = arch::get_tcb() as *mut ThreadControlBlock;
            assert!(!tcb.is_null(), "Don't have TCB available?");
            &mut *tcb
        }
    }

    // TODO(correctness): this needs some hardending to avoid aliasing of ThreadState!
    pub fn scheduler<'a>() -> &'a SchedulerControlBlock {
        unsafe {
            let scb = arch::get_scb() as *mut SchedulerControlBlock;
            assert!(!scb.is_null(), "Don't have SCB state available?");
            assert!(
                (scb as u64) < KERNEL_BASE,
                "Something wrong with the scb, points to kernel address"
            );
            &*scb
        }
    }

    // This method returns the core-id for the current thread. It is needed because
    // SchedulerControlBlock allocates an ArrayQueue and that leads to recursive fault.
    pub fn core_id() -> CoreId {
        unsafe {
            let scb = arch::get_scb() as *const SchedulerControlBlock;
            if !scb.is_null() && (scb as u64) < KERNEL_BASE {
                (*scb).core_id
            } else {
                kpi::syscalls::System::core_id().expect("Can't get core-id?")
            }
        }
    }
}

#[test]
#[ignore]
fn test_tls() {
    let _r = env_logger::try_init();
    use crate::scheduler::SmpScheduler;
    use crate::stack::DEFAULT_STACK_SIZE_BYTES;
    use crate::tls2::Environment;

    let s: SmpScheduler = Default::default();

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            let s = Environment::scheduler();
            s.rump_upcalls
                .store(0xdead as *mut u64, core::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                Environment::scheduler()
                    .rump_upcalls
                    .load(Ordering::Relaxed),
                0xdead as *mut u64
            );
            for _i in 0..5 {
                // Thread control-block (and tid) should change:
                assert_eq!(Environment::tid(), ThreadId(1));
                // Force context switch:
                Environment::thread().relinquish();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    s.spawn(
        DEFAULT_STACK_SIZE_BYTES,
        move |_yielder| {
            let _s = Environment::scheduler();
            // Scheduler should be preserved across threads
            assert_eq!(
                Environment::scheduler()
                    .rump_upcalls
                    .load(Ordering::Relaxed),
                0xdead as *mut u64
            );
            for _i in 0..5 {
                // Thread control-block (and tid) should change
                assert_eq!(Environment::tid(), ThreadId(2));
                // Force context switch:
                Environment::thread().relinquish();
            }
        },
        ptr::null_mut(),
        0,
        None,
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    for _i in 0..10 {
        s.run(&scb);
    }
}
