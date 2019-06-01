use crate::alloc::alloc;
use core::alloc::Layout;
use core::arch::x86_64::_rdrand16_step;
use core::ffi::VaList;
use core::ptr;
use core::slice;

use cstr_core::CStr;

use log::{error, info, trace};

use lineup::mutex::Mutex;

pub mod dev;
pub mod fs;
pub mod locking;
pub mod threads;

pub enum RumpError {
    ENOENT = 2,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    EBADF = 9,
    ENOMEM = 12,
    EBUSY = 16,
    EINVAL = 22, // same as EGENERIC
    EROFS = 30,
    ETIMEDOUT = 60,
    ENOSYS = 78,
}

const RUMPUSER_CLOCK_RELWALL: u64 = 0;
const RUMPUSER_CLOCK_ABSMONO: u64 = 1;

#[allow(non_camel_case_types)]
pub type pid_t = u64;
#[allow(non_camel_case_types)]
pub type c_int = i32;
#[allow(non_camel_case_types)]
pub type c_uint = u32;
#[allow(non_camel_case_types)]
pub type c_long = i64;
#[allow(non_camel_case_types)]
pub type c_ulong = u64;
#[allow(non_camel_case_types)]
pub type c_void = u64;
#[allow(non_camel_case_types)]
pub type c_char = u8;
#[allow(non_camel_case_types)]
pub type c_size_t = u64;

/// typedef void (*rump_biodone_fn)(void *, size_t, int);
#[allow(non_camel_case_types)]
type rump_biodone_fn = Option<unsafe extern "C" fn(*mut c_void, c_size_t, c_int)>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RumpHyperUpcalls {
    pub hyp_schedule: Option<unsafe extern "C" fn()>,
    pub hyp_unschedule: Option<unsafe extern "C" fn()>,
    pub hyp_backend_unschedule:
        Option<unsafe extern "C" fn(arg1: c_int, arg2: *mut c_int, arg3: *const c_void)>,
    pub hyp_backend_schedule: Option<unsafe extern "C" fn(arg1: c_int, arg2: *const c_void)>,
    pub hyp_lwproc_switch: Option<unsafe extern "C" fn(arg1: *mut threads::lwp)>,
    pub hyp_lwproc_release: Option<unsafe extern "C" fn()>,
    pub hyp_lwproc_rfork:
        Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: c_int, arg3: *const c_char) -> c_int>,
    pub hyp_lwproc_newlwp: Option<unsafe extern "C" fn(arg1: pid_t) -> c_int>,
    pub hyp_lwproc_curlwp: Option<unsafe extern "C" fn() -> *mut threads::lwp>,
    pub hyp_syscall:
        Option<unsafe extern "C" fn(arg1: c_int, arg2: *mut c_void, arg3: *mut c_long) -> c_int>,
    pub hyp_lwpexit: Option<unsafe extern "C" fn()>,
    pub hyp_execnotify: Option<unsafe extern "C" fn(arg1: *const c_char)>,
    pub hyp_getpid: Option<unsafe extern "C" fn() -> pid_t>,
    pub hyp_extra: [*mut c_void; 8usize],
}

#[allow(unused)]
pub fn rumpkern_curlwp() -> u64 {
    unsafe { threads::rumpuser_curlwp() as *const _ as u64 }
}

pub fn rumpkern_unsched(nlocks: &mut i32, mtx: Option<&Mutex>) {
    let s = lineup::tls::Environment::scheduler();
    let upcalls = s.rump_upcalls as *const RumpHyperUpcalls;

    let mtx = mtx.map_or(ptr::null(), |mtx| mtx as *const Mutex);
    unsafe {
        trace!(
            "rumpkern_unsched {} {:p} lwp={:p}",
            *nlocks,
            mtx,
            threads::rumpuser_curlwp()
        );
        (*upcalls).hyp_backend_unschedule.unwrap()(0, nlocks as *mut c_int, mtx as *const u64);
    }
}

pub fn rumpkern_sched(nlocks: &i32, mtx: Option<&Mutex>) {
    let s = lineup::tls::Environment::scheduler();
    let upcalls = s.rump_upcalls as *const RumpHyperUpcalls;

    let mtx = mtx.map_or(ptr::null(), |mtx| mtx as *const Mutex);
    trace!("rumpkern_sched {} {:p}", *nlocks, mtx);
    unsafe {
        (*upcalls).hyp_backend_schedule.unwrap()(*nlocks, mtx as *const u64);
    }
}

// int rumpuser_init(int version, struct rump_hyperup *hyp)
#[no_mangle]
pub(crate) unsafe extern "C" fn rumpuser_init(version: i64, hyp: *const RumpHyperUpcalls) -> i64 {
    info!("rumpuser_init ver {} {:p}", version, hyp);

    let s = lineup::tls::Environment::scheduler();
    s.set_rump_context(version, hyp as *const u64);

    0
}

// int rumpuser_malloc(size_t len, int alignment, void **memp)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_malloc(len: usize, alignment: usize, memp: *mut *mut u8) -> i64 {
    assert!(
        len >= alignment,
        "If this doesn't hold we need a smarter deallocate method for buddy alloc"
    );

    let ptr = alloc::alloc(Layout::from_size_align_unchecked(len, alignment));
    *memp = ptr;
    0
    // ENOMEM if OOM
}

// void rumpuser_free(void *mem, size_t len)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_free(ptr: *mut u8, len: usize) {
    // We don't get the alignment on free here so we assume
    // alignment == 1, this is fine as long as rumpuser_malloc always
    // allocs with len >= alignment (see assertion there).

    trace!("rumpuser_free len={}", len);
    alloc::dealloc(ptr, Layout::from_size_align_unchecked(len, 1));
}

/// int rumpuser_getrandom(void *buf, size_t buflen, int flags, size_t *retp)
///
/// buf              buffer that the randomness is written to
/// buflen           number of bytes of randomness requested
/// flags            The value 0 or a combination of RUMPUSER_RANDOM_HARD
///                  (return true randomness instead of something from a
///                  PRNG) and RUMPUSER_RANDOM_NOWAIT (do not block in case
///                  the requested amount of bytes is not available).
/// retp             The number of random bytes written into buf.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_getrandom(
    buf: *mut u8,
    buflen: usize,
    _flags: i64,
    retp: *mut usize,
) -> i64 {
    trace!("rumpuser_getrandom");

    let region: &mut [u8] = slice::from_raw_parts_mut(buf, buflen);
    for (i, ptr) in region.iter_mut().enumerate() {
        let mut rnd: u16 = 0xba;
        let ret = _rdrand16_step(&mut rnd);
        if ret == 1 {
            *ptr = rnd as u8;
        } else {
            *retp = i.checked_sub(1).unwrap_or(0);
            return 1;
        }
    }

    *retp = buflen;
    0
}

/// void rumpuser_putchar(int ch)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_putchar(ch: i64) {
    let mut buf: [u8; 4] = [0; 4]; // A buffer of length 4 is large enough to encode any char
    if ch as i64 == '\n' as u8 as i64 {
        let utf8_char = '\r'.encode_utf8(&mut buf);
        crate::syscalls::print(utf8_char);
    }
    let utf8_char = (ch as u8 as char).encode_utf8(&mut buf);
    crate::syscalls::print(utf8_char);
}

/// void rumpuser_dprintf(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_dprintf(fmt: *const i8, _ap: VaList) {
    //use core::intrinsics::VaList;
    let fmt = CStr::from_ptr(fmt).to_str().unwrap_or("");
    crate::sys_println!(" rumpuser_dprintf {}", fmt);
}

/// int rumpuser_clock_gettime(int enum_rumpclock, int64_t *sec, long *nsec)
/// enum_rumpclock   specifies the clock type.
///
/// In case of RUMPUSER_CLOCK_RELWALL the wall time should be returned.
/// In case of RUMPUSER_CLOCK_ABSMONO the time of a mono-tonic clock should be returned.
///
/// sec return value for seconds
/// nsec return value for nanoseconds
#[no_mangle]
pub unsafe extern "C" fn rumpuser_clock_gettime(
    enum_rumpclock: u64,
    sec: *mut i64,
    nsec: *mut u64,
) -> i64 {
    //trace!("rumpuser_clock_gettime");

    let boot_time = rawtime::duration_since_boot();

    match enum_rumpclock {
        RUMPUSER_CLOCK_ABSMONO => {
            *sec = boot_time.as_secs() as i64;
            *nsec = boot_time.subsec_nanos() as u64;
            0
        }
        RUMPUSER_CLOCK_RELWALL => {
            //*sec = ((*rawtime::WALL_TIME_ANCHOR).as_unix_time() + boot_time.as_secs()) as i64;
            *sec = boot_time.as_secs() as i64;
            *nsec = boot_time.subsec_nanos() as u64;
            0
        }
        _ => 1,
    }
}

/// int rumpuser_getparam(const char *name, void *buf, size_t buflen)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_getparam(
    //name: *const cstr_core::c_char,
    name: *const i8,
    buf: *mut u8,
    len: usize,
) -> usize {
    let param_name = CStr::from_ptr(name).to_str().unwrap_or("");
    trace!("rumpuser_getparam {}", param_name);

    let cstr = match param_name {
        "_RUMPUSER_NCPU" => CStr::from_bytes_with_nul_unchecked(b"1\0"),
        "RUMP_VERBOSE" => CStr::from_bytes_with_nul_unchecked(b"1\0"),
        "RUMP_THREADS" => CStr::from_bytes_with_nul_unchecked(b"1\0"),
        "_RUMPUSER_HOSTNAME" => CStr::from_bytes_with_nul_unchecked(b"btest\0"),
        "RUMP_MEMLIMIT" => CStr::from_bytes_with_nul_unchecked(b"134217728\0"), // 128 MiB
        //"RUMP_MEMLIMIT" => CStr::from_bytes_with_nul_unchecked(b"2097152\0"), // 2MIB
        //"RUMP_MEMLIMIT" => CStr::from_bytes_with_nul_unchecked(b"197152\0"), // 2MIB
        _ => return RumpError::ENOENT as usize,
    };

    assert!(len >= cstr.to_bytes_with_nul().len());
    let buf_slice = slice::from_raw_parts_mut(buf, cstr.to_bytes_with_nul().len());
    buf_slice.copy_from_slice(cstr.to_bytes_with_nul());
    0
}

/// void rumpuser_exit(int value)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_exit(value: i64) {
    unreachable!("rumpuser_exit({})", value);
}

/// int rumpuser_kill(int64_t pid, int sig)
#[no_mangle]
pub unsafe extern "C" fn rumpuser_kill(pid: i64, sig: isize) -> isize {
    unreachable!("rumpuser_kill({}, {})", pid, sig);
}

// No need to implement:
#[no_mangle]
pub unsafe extern "C" fn rumpuser_anonmmap() {
    unreachable!("rumpuser_anonmmap");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_unmap() {
    unreachable!("rumpuser_anonmmap");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_daemonize_begin() {
    unreachable!("rumpuser_daemonize_begin");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_daemonize_done() {
    unreachable!("rumpuser_daemonize_done");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_dl_bootstrap() -> i64 {
    trace!("rumpuser_dl_bootstrap");
    0
}

#[cfg(test)]
mod test {
    use crate::rumprt::*;

    #[test]
    fn test_random() {
        unsafe {
            let mut buf: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            let mut ret: usize = 0;
            rumpuser_getrandom(buf.as_mut_ptr(), 4, 0, &mut ret);
            assert_eq!(ret, 4);
            assert!(
                buf[0] != 0
                    && buf[1] != 0
                    && buf[2] != 0
                    && buf[3] != 0
                    && buf[4] == 0
                    && buf[5] == 0
                    && buf[6] == 0
                    && buf[7] == 0
            );
        }
    }

    #[test]
    fn test_putchar() {
        unsafe {
            rumpuser_putchar('a' as i64);
            rumpuser_putchar('b' as i64);
            rumpuser_putchar('c' as i64);
        }
    }

}
