use crate::{ThreadId, ThreadState};
use core::ptr;
use core::sync::atomic::AtomicBool;

use log::trace;

#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "unix")]
pub use crate::tls::unix as arch;

#[cfg(target_os = "bespin")]
pub mod bespin;
#[cfg(target_os = "bespin")]
pub use crate::tls::bespin as arch;

#[cfg(target_os = "none")]
pub mod x86_64;
#[cfg(target_os = "none")]
pub use crate::tls::x86_64 as arch;

pub struct ThreadLocalStorage<'a> {
    thread: *mut ThreadState<'a>,
    scheduler: *mut SchedulerState,
}

impl<'a> ThreadLocalStorage<'a> {
    pub fn new() -> ThreadLocalStorage<'a> {
        ThreadLocalStorage {
            thread: ptr::null_mut(),
            scheduler: ptr::null_mut(),
        }
    }
}

// TODO: this needs some hardending to avoid aliasing of ThreadState!
pub(crate) unsafe fn get_thread_state<'a>() -> *mut ThreadState<'a> {
    let raw_tls = arch::get_tls();
    assert!(!raw_tls.is_null(), "Don't have TLS?");

    let ts: &mut ThreadLocalStorage = &mut *raw_tls;
    assert!(!ts.thread.is_null(), "Don't have thread state available?");
    ts.thread
}

pub(crate) unsafe fn set_thread_state(t: *mut ThreadState) {
    let raw_tls = arch::get_tls();
    assert!(!raw_tls.is_null(), "Don't have TLS?");
    let ts: &mut ThreadLocalStorage = &mut *raw_tls;
    ts.thread = t;
}

unsafe fn get_scheduler_state<'a>() -> *mut SchedulerState {
    let raw_tls = arch::get_tls();
    assert!(!raw_tls.is_null(), "Don't have TLS available?");

    let ts: &mut ThreadLocalStorage = &mut *raw_tls;
    assert!(
        !ts.scheduler.is_null(),
        "Don't have scheduler state available?"
    );
    ts.scheduler
}

pub(crate) unsafe fn set_scheduler_state(s: *mut SchedulerState) {
    let raw_tls = arch::get_tls();
    assert!(!raw_tls.is_null(), "Don't have TLS?");
    let ts: &mut ThreadLocalStorage = &mut *raw_tls;
    ts.scheduler = s;
}

pub struct Environment {}

impl Environment {
    pub fn tid() -> ThreadId {
        unsafe {
            let ts = arch::get_tls();
            assert!(!ts.is_null(), "Don't have thread state available?");
            (*(*ts).thread).tid
        }
    }

    // TODO: this needs some hardending to avoid aliasing of ThreadState!
    pub fn thread<'a>() -> &'a mut ThreadState<'a> {
        unsafe { &mut *get_thread_state() }
    }

    // TODO: this needs some hardending to avoid aliasing of ThreadState!
    pub fn scheduler<'a>() -> &'a mut SchedulerState {
        unsafe { &mut *get_scheduler_state() }
    }
}

#[derive(Debug)]
pub struct SchedulerState {
    pub signal_irq: AtomicBool,
    pub rump_upcalls: *const u64,
    pub rump_version: i64,
    pub(crate) make_runnable: crate::ds::Vec<ThreadId>,
}

impl SchedulerState {
    pub fn new() -> SchedulerState {
        SchedulerState {
            signal_irq: AtomicBool::new(false),
            rump_upcalls: ptr::null(),
            rump_version: 0,
            make_runnable: crate::ds::Vec::with_capacity(crate::Scheduler::MAX_THREADS),
        }
    }

    pub fn set_rump_context(&mut self, version: i64, upcall_ptr: *const u64) {
        self.rump_version = version;
        self.rump_upcalls = upcall_ptr;
        assert!(!self.rump_upcalls.is_null());
    }

    pub fn add_to_runlist(&mut self, tid: ThreadId) {
        trace!("add_to_runlist {:?}", tid);
        self.make_runnable.push(tid);
    }
}

#[test]
fn test_tls() {
    use crate::DEFAULT_UPCALLS;
    let mut s = crate::Scheduler::new(DEFAULT_UPCALLS);

    s.spawn(
        4096,
        move |mut yielder| {
            let s = Environment::scheduler();
            s.rump_upcalls = 0xdead as *mut u64;
            for _i in 0..5 {
                println!("{:?}", Environment::scheduler());
                println!("{:?}", Environment::thread());
            }
        },
        ptr::null_mut(),
    );

    s.spawn(
        4096,
        move |mut yielder| {
            let s = Environment::scheduler();
            s.rump_upcalls = 0xbeef as *mut u64;
            for _i in 0..5 {
                println!("{:?}", Environment::scheduler());
                println!("{:?}", Environment::thread());
            }
        },
        ptr::null_mut(),
    );

    for _i in 0..10 {
        s.run();
    }
}
