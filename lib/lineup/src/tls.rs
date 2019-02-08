use crate::{ThreadId, ThreadState};
use x86::bits64::segmentation;

pub(crate) unsafe fn get_thread_state<'a>() -> *mut ThreadState<'a> {
    segmentation::rdgsbase() as *mut ThreadState<'a>
}

pub(crate) unsafe fn set_thread_state(t: *mut ThreadState) {
    segmentation::wrgsbase(t as u64)
}

pub struct Environment {}

impl Environment {
    pub fn tid() -> ThreadId {
        unsafe {
            let ts = get_thread_state();
            assert!(!ts.is_null(), "Don't have thread state available?");
            (*ts).tid
        }
    }

    // TODO: this needs some hardending to avoid aliasing of ThreadState!
    pub fn thread<'a>() -> &'a mut ThreadState<'a> {
        unsafe {
            let ts = get_thread_state();
            assert!(!ts.is_null(), "Don't have thread state available?");
            &mut *ts
        }
    }
}
