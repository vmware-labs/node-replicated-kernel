use super::*;
use core::mem;
use core::ptr;

use lineup::tls::Environment;

pub unsafe extern "C" fn thread_create(
    fun: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    arg: *mut c_void,
) -> lkl_thread_t {
    trace!("lkl thread_create {:?} {:p}", fun, arg);

    // TODO: Make a proper wrapper
    let fun = mem::transmute::<
        Option<unsafe extern "C" fn(arg1: *mut c_void)>,
        Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
    >(fun);

    let s = lineup::tls::Environment::thread();
    let tid = s.spawn(fun, arg as *mut u8);

    trace!("lkl thread_create'd id {:?}", tid.unwrap().0);

    tid.unwrap().0 as lkl_thread_t
}

pub unsafe extern "C" fn thread_detach() {
    unreachable!("lkl thread_detach");
}

pub unsafe extern "C" fn thread_exit() {
    unreachable!("lkl thread_exit");
}

pub unsafe extern "C" fn thread_join(tid: lkl_thread_t) -> c_int {
    unreachable!("lkl thread_join");
    0
}

pub unsafe extern "C" fn thread_self() -> lkl_thread_t {
    trace!("lkl thread_self");
    Environment::tid().0 as lkl_thread_t
}

pub unsafe extern "C" fn thread_equal(a: lkl_thread_t, b: lkl_thread_t) -> c_int {
    trace!("lkl thread_equal");

    if a == b {
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn tls_alloc(
    destructor: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
) -> *mut lkl_tls_key {
    unreachable!("lkl tls_alloc");
    ptr::null_mut()
}

pub unsafe extern "C" fn tls_free(key: *mut lkl_tls_key) {
    unreachable!("lkl tls_free");
}

pub unsafe extern "C" fn tls_set(key: *mut lkl_tls_key, data: *mut c_void) -> c_int {
    unreachable!("lkl tls_set");
    0
}

pub unsafe extern "C" fn tls_get(key: *mut lkl_tls_key) -> *mut c_void {
    unreachable!("lkl tls_get");
    ptr::null_mut()
}

pub unsafe extern "C" fn gettid() -> c_long {
    unreachable!("lkl gettid");
    Environment::tid().0 as i64
}

pub unsafe extern "C" fn jmp_buf_set(jmpb: *mut lkl_jmp_buf, f: Option<unsafe extern "C" fn()>) {
    unreachable!("lkl jmp_buf_set");
}

pub unsafe extern "C" fn jmp_buf_longjmp(jmpb: *mut lkl_jmp_buf, val: c_int) {
    unreachable!("lkl jmp_buf_longjmp");
}
