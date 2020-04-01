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
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use fringe::generator::Yielder;

use rawtime::{Duration, Instant};

use crate::stack::LineupStack;
use crate::{CoreId, ThreadId, Upcalls, YieldRequest, YieldResume};

#[cfg(target_os = "bespin")]
pub mod bespin;
#[cfg(target_os = "bespin")]
pub use crate::tls2::bespin as arch;

#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "unix")]
pub use crate::tls2::unix as arch;

/// Per thread state of the scheduler.
///
/// This is what the `fs` register points to.
/// The thread-local-storage region is allocated
/// in front of that structure (since we do the TLS variant 2).
pub struct ThreadControlBlock<'a> {
    pub(crate) yielder: &'a Yielder<YieldResume, YieldRequest>,
    pub(crate) tid: ThreadId,

    pub current_core: CoreId,
    pub upcalls: Upcalls,
    pub rump_lwp: *const u64,
    pub rumprun_lwp: *const u64,
}

impl<'a> ThreadControlBlock<'a> {
    fn yielder(&self) -> &'a Yielder<YieldResume, YieldRequest> {
        self.yielder
    }

    pub fn set_lwp(&mut self, lwp_ptr: *const u64) {
        self.rump_lwp = lwp_ptr;
    }

    pub fn spawn_with_stack(
        &self,
        s: LineupStack,
        f: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
        arg: *mut u8,
    ) -> Option<ThreadId> {
        let request = YieldRequest::SpawnWithStack(s, f, arg, 0);
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
        let request = YieldRequest::Spawn(f, arg, 0);
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
    pub signal_irq: AtomicBool,
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
            signal_irq: AtomicBool::new(false),
            rump_upcalls: AtomicPtr::new(ptr::null_mut()),
            core_id,
        }
    }
}

impl SchedulerControlBlock {
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
    pub fn tid() -> ThreadId {
        unsafe {
            let ts = arch::get_tcb();
            assert!(!ts.is_null(), "Don't have TCB available?");
            (*ts).tid
        }
    }

    // TODO(correctness): this needs some hardending to avoid aliasing of ThreadState!
    pub fn thread<'a>() -> &'a mut ThreadControlBlock<'static> {
        unsafe {
            let tcb = arch::get_tcb();
            assert!(!tcb.is_null(), "Don't have TCB available?");
            &mut *tcb
        }
    }

    // TODO(correctness): this needs some hardending to avoid aliasing of ThreadState!
    pub fn scheduler<'a>() -> &'a SchedulerControlBlock {
        unsafe {
            let scb = arch::get_scb();
            assert!(!scb.is_null(), "Don't have SCB state available?");
            &*scb
        }
    }
}

#[test]
fn test_tls() {
    let _r = env_logger::try_init();
    use crate::tls2::Environment;
    use crate::{DEFAULT_STACK_SIZE_BYTES, DEFAULT_UPCALLS};

    let s = crate::smp::SmpScheduler::new(DEFAULT_UPCALLS);

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
    );

    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    for _i in 0..10 {
        s.run(&scb);
    }
}
