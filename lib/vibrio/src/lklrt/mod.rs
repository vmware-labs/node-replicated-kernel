use crate::alloc::alloc;
use crate::alloc::boxed::Box;

use core::alloc::Layout;
use core::ptr;
use core::slice;

use lkl::*;

pub mod dev;
pub mod locking;
pub mod threads;

use cstr_core::CStr;

use lineup::tls::Environment;
use rawtime::{Duration, Instant};

/*
#[cfg(all(feature = "integration-test", feature = "test-linux"))]
pub fn xmain() {
    use cstr_core::CStr;

    extern "C" {
        // int __init lkl_start_kernel(struct lkl_host_operations *ops, const char *fmt, ...)
        fn lkl_start_kernel(ops: *const lkl::lkl_host_operations, fmt: *const i8) -> i32;
        fn lkl_sys_halt();
    }

    let up = lineup::DEFAULT_UPCALLS;

    let mut scheduler = lineup::Scheduler::new(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let linux_ops = linuxrt::get_host_ops();
            let boot_arg = CStr::from_bytes_with_nul(b"mem=16M loglevel=8\0");
            let r = lkl_start_kernel(&linux_ops, boot_arg.unwrap().as_ptr());
            info!("lkl_start_kernel {}", r);

            arch::debug::shutdown(ExitReason::Ok);
        },
        core::ptr::null_mut(),
    );

    loop {
        scheduler.run();
    }
}
*/

#[no_mangle]
pub unsafe extern "C" fn lkl_bug(fmt: *const i8) {
    info!("lkl_bug");
}

#[no_mangle]
pub unsafe extern "C" fn lkl_printf(fmt: *const i8) {
    info!("lkl_printf");
}

#[no_mangle]
pub unsafe extern "C" fn print(fmt: *const c_char, len: c_int) {
    let len = len as usize;
    let slice: &[u8] = slice::from_raw_parts(fmt, len);

    // TODO: `fmt` is *not* null terminated so we do some trickery below with
    // printing, I'm not sure if this is a problem for cstr_core for how
    // we're using it here:
    let fmt_conv = CStr::from_bytes_with_nul_unchecked(slice)
        .to_str()
        .unwrap_or("unknown");

    info!("{fmt:.*}", len, fmt = fmt_conv);
}

pub unsafe extern "C" fn panic() {
    error!("lkl panic");
    loop {
        Environment::thread().relinquish()
    }
}

pub unsafe extern "C" fn mem_alloc(len: c_ulong) -> *mut c_void {
    trace!("lkl mem_alloc len = {}", len);

    alloc::alloc(Layout::from_size_align_unchecked(len as usize, 8)) as *mut c_void
}

pub unsafe extern "C" fn mem_free(ptr: *mut c_void) {
    trace!("lkl mem_free arg = {:p}", ptr);
    //alloc::dealloc(ptr, Layout::from_size_align_unchecked(len, 1));
}

use core::sync::atomic::{AtomicUsize, Ordering};
static CNTR: AtomicUsize = AtomicUsize::new(0);

pub unsafe extern "C" fn lkl_time() -> c_ulonglong {
    trace!("lkl time");

    CNTR.fetch_add(1, Ordering::SeqCst);

    if CNTR.load(Ordering::SeqCst) > 118 {
        crate::panic::backtrace();
    }

    Instant::now().as_nanos() as u64
}

struct Timer {
    xfn: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    xarg: *mut c_void,
    wakeup_time: Duration,
}

impl Timer {
    fn new(xfn: Option<unsafe extern "C" fn(arg1: *mut c_void)>, xarg: *mut c_void) -> Timer {
        Timer {
            xfn: xfn,
            xarg: xarg,
            wakeup_time: Duration::from_nanos(0),
        }
    }
}

pub unsafe extern "C" fn timer_alloc(
    tfn: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    targ: *mut c_void,
) -> *mut c_void {
    let alloc_timer: Box<Timer> = Box::new(Timer::new(tfn, targ));
    let timer = Box::into_raw(alloc_timer) as *mut c_void;
    trace!("lkl timer_alloc {:p} tfn={:?} targ={:p}", timer, tfn, targ);

    timer
}

unsafe extern "C" fn timer_call(timer_ptr: *mut u8) -> *mut u8 {
    let timer = timer_ptr as *mut Timer;
    //let wait_until = (*timer)->wakeup;

    let t = Environment::thread().sleep((*timer).wakeup_time);
    trace!("timer call woken up");

    let timer_fn = (*timer).xfn.unwrap();

    timer_fn((*timer).xarg);
    ptr::null_mut()

    //let t = Environment::thread();
}

pub unsafe extern "C" fn timer_set_oneshot(timer: *mut c_void, delta: c_ulong) -> c_int {
    trace!("lkl timer_set_oneshot delta = {}", delta);

    let duration = Duration::from_nanos(delta);
    let timer = timer as *mut Timer;
    (*timer).wakeup_time = duration;

    let s = lineup::tls::Environment::thread();
    let tid = s.spawn(Some(timer_call), timer as *mut u8);

    0
}

pub unsafe extern "C" fn timer_free(timer: *mut c_void) {
    trace!("lkl timer_free {:p}", timer);
    let to_free = Box::from_raw(timer);
    drop(to_free);
}

pub(crate) fn get_host_ops() -> lkl_host_operations {
    lkl_host_operations {
        virtio_devices: ptr::null(),
        print: Some(print),
        panic: Some(panic),
        sem_alloc: Some(locking::sem_alloc),
        sem_free: Some(locking::sem_free),
        sem_up: Some(locking::sem_up),
        sem_down: Some(locking::sem_down),
        mutex_alloc: Some(locking::mutex_alloc),
        mutex_free: Some(locking::mutex_free),
        mutex_lock: Some(locking::mutex_lock),
        mutex_unlock: Some(locking::mutex_unlock),
        thread_create: Some(threads::thread_create),
        thread_detach: Some(threads::thread_detach),
        thread_exit: Some(threads::thread_exit),
        thread_join: Some(threads::thread_join),
        thread_self: Some(threads::thread_self),
        thread_equal: Some(threads::thread_equal),
        tls_alloc: Some(threads::tls_alloc),
        tls_free: Some(threads::tls_free),
        tls_set: Some(threads::tls_set),
        tls_get: Some(threads::tls_get),
        mem_alloc: Some(mem_alloc),
        mem_free: Some(mem_free),
        time: Some(lkl_time),
        timer_alloc: Some(timer_alloc),
        timer_set_oneshot: Some(timer_set_oneshot),
        timer_free: Some(timer_free),
        ioremap: Some(dev::ioremap),
        iomem_access: Some(dev::iomem_access),
        gettid: Some(threads::gettid),
        jmp_buf_set: Some(threads::jmp_buf_set),
        jmp_buf_longjmp: Some(threads::jmp_buf_longjmp),
    }
}
