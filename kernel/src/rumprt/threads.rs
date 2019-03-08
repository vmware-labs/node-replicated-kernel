use core::ops::Add;
use cstr_core::CStr;
use lineup::tls::Environment;
use rawtime::Duration;

#[allow(non_camel_case_types)]
pub type rumplwpop = u32;

pub const RUMPLWPOP_RUMPUSER_LWP_CREATE: rumplwpop = 0;
pub const RUMPLWPOP_RUMPUSER_LWP_DESTROY: rumplwpop = 1;
pub const RUMPLWPOP_RUMPUSER_LWP_SET: rumplwpop = 2;
pub const RUMPLWPOP_RUMPUSER_LWP_CLEAR: rumplwpop = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lwp {
    _unused: [u8; 0],
}

/// Create a schedulable host thread context. The rump kernel will call
/// this interface when it creates a kernel thread.
/// The scheduling policy for the new thread is defined by the hypervisor.
/// In case the hypervisor wants to optimize the scheduling of the threads,
/// it can perform heuristics on the thrname, priority and cpuidx parameters.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_create(
    fun: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
    arg: *mut u8,
    name: *const u8,
    mustjoin: i64,
    priority: i64,
    cpuidx: i64,
    cookie: *mut *mut u8,
) -> i64 {
    let tname = CStr::from_ptr(name as *const i8)
        .to_str()
        .unwrap_or("[unknown]");
    trace!(
        "rumpuser_thread_create {} {:?} {:p} join={} prio={} cpu={} cookie={:p}",
        tname,
        fun,
        arg,
        mustjoin,
        priority,
        cpuidx,
        cookie
    );

    let s = lineup::tls::Environment::thread();
    s.spawn(fun, arg);

    0
}

/// Called when a thread created with rumpuser_thread_create() exits.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_exit() {
    let t = lineup::tls::Environment::thread();
    loop {
        t.block();
    }
    //unreachable!("rumpuser_thread_exit");
}

/// Wait for a joinable thread to exit. The cookie matches the value from rumpuser_thread_create().
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_join(cookie: *mut u8) -> i64 {
    unreachable!("rumpuser_thread_join");
    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwpop(op: rumplwpop, lwp: *const lwp) -> i64 {
    error!(
        "{:?} rumpuser_curlwpop op={} lwp={:p}",
        lineup::tls::Environment::tid(),
        op,
        lwp
    );
    let t = lineup::tls::Environment::thread();

    if op == RUMPLWPOP_RUMPUSER_LWP_SET {
        t.set_lwp(lwp as *const u64);
    }
    if op == RUMPLWPOP_RUMPUSER_LWP_CLEAR {
        assert!(t.rump_lwp == lwp as *const u64);
        t.set_lwp(core::ptr::null());
    }

    0
}

/*
979148367 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=SET lwp=0xffffffff803a0b40
980654579 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=CREAT lwp=0xffffffff8273c000
982041302 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=CLEAR lwp=0xffffffff803a0b40
983427129 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=SET lwp=0xffffffff8273c000
984934736 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=CREAT lwp=0xffffffff8273d800
986337116 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=CLEAR lwp=0xffffffff8273c000
987740425 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=SET lwp=0xffffffff8273d800
989263375 [ERROR] - bespin::rumprt::threads: ThreadId(1) rumpuser_curlwpop op=DESTROY lwp=0xffffffff8273c000
*/

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwp() -> *mut lwp {
    //debug!("rumpuser_curlwp");
    let t = lineup::tls::Environment::thread();
    if lineup::tls::Environment::tid() == lineup::ThreadId(1) {
        info!("rumpuser_curlwp for tid#1 = {:p}", t.rump_lwp);
    }
    t.rump_lwp as *mut lwp
}

/// int rumpuser_clock_sleep(int enum_rumpclock, int64_t sec, long nsec)
///
/// enum_rumpclock   In case of RUMPUSER_CLOCK_RELWALL, the sleep should last
/// at least as long as specified.  In case of
/// RUMPUSER_CLOCK_ABSMONO, the sleep should last until the
/// hypervisor monotonic clock hits the specified absolute
/// time.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_clock_sleep(enum_rumpclock: u64, sec: i64, nanos: u64) -> isize {
    trace!(
        "{:?} rumpuser_clock_sleep({}, {}, {})",
        Environment::tid(),
        enum_rumpclock,
        sec,
        nanos
    );
    // TODO: ignored _enum_rumpclock

    let mut nlocks = 0;
    super::rumpkern_unsched(&mut nlocks, None);

    let d = Duration::from_secs(sec as u64).add(Duration::from_nanos(nanos));
    let t = Environment::thread();
    t.sleep(d);
    super::rumpkern_sched(&nlocks, None);
    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_seterrno(errno: isize) {
    info!("rumpuser_seterrno {}", errno);
}

// #define	EPERM		1		/* Operation not permitted */
// #define	ENOENT		2		/* No such file or directory */
// #define	ESRCH		3		/* No such process */
// #define	EINTR		4		/* Interrupted system call */
// #define	EIO		5		/* Input/output error */
// #define	ENXIO		6		/* Device not configured */
// #define	E2BIG		7		/* Argument list too long */
// #define	ENOEXEC		8		/* Exec format error */
// #define	EBADF		9		/* Bad file descriptor */
// #define	ECHILD		10		/* No child processes */
// #define	EDEADLK		11		/* Resource deadlock avoided */
// /* 11 was EAGAIN */
// #define	ENOMEM		12		/* Cannot allocate memory */
// #define	EACCES		13		/* Permission denied */
// #define	EFAULT		14		/* Bad address */
// #define	ENOTBLK		15		/* Block device required */
// #define	EBUSY		16		/* Device busy */
// #define	EEXIST		17		/* File exists */
// #define	EXDEV		18		/* Cross-device link */
// #define	ENODEV		19		/* Operation not supported by device */
// #define	ENOTDIR		20		/* Not a directory */
// #define	EISDIR		21		/* Is a directory */
// #define	EINVAL		22		/* Invalid argument */
// #define	ENFILE		23		/* Too many open files in system */
// #define	EMFILE		24		/* Too many open files */
// #define	ENOTTY		25		/* Inappropriate ioctl for device */
// #define	ETXTBSY		26		/* Text file busy */
// #define	EFBIG		27		/* File too large */
// #define	ENOSPC		28		/* No space left on device */
// #define	ESPIPE		29		/* Illegal seek */
// #define	EROFS		30		/* Read-only file system */
// #define	EMLINK		31		/* Too many links */
// #define	EPIPE		32		/* Broken pipe */
//
// /* math software */
// #define	EDOM		33		/* Numerical argument out of domain */
// #define	ERANGE		34		/* Result too large or too small */
//
// /* non-blocking and interrupt i/o */
// #define	EAGAIN		35		/* Resource temporarily unavailable */
// #define	EWOULDBLOCK	EAGAIN		/* Operation would block */
// #define	EINPROGRESS	36		/* Operation now in progress */
// #define	EALREADY	37		/* Operation already in progress */
//
// /* ipc/network software -- argument errors */
// #define	ENOTSOCK	38		/* Socket operation on non-socket */
// #define	EDESTADDRREQ	39		/* Destination address required */
// #define	EMSGSIZE	40		/* Message too long */
// #define	EPROTOTYPE	41		/* Protocol wrong type for socket */
// #define	ENOPROTOOPT	42		/* Protocol option not available */
// #define	EPROTONOSUPPORT	43		/* Protocol not supported */
// #define	ESOCKTNOSUPPORT	44		/* Socket type not supported */
// #define	EOPNOTSUPP	45		/* Operation not supported */
// #define	EPFNOSUPPORT	46		/* Protocol family not supported */
// #define	EAFNOSUPPORT	47		/* Address family not supported by protocol family */
// #define	EADDRINUSE	48		/* Address already in use */
// #define	EADDRNOTAVAIL	49		/* Can't assign requested address */
//
// /* ipc/network software -- operational errors */
// #define	ENETDOWN	50		/* Network is down */
// #define	ENETUNREACH	51		/* Network is unreachable */
// #define	ENETRESET	52		/* Network dropped connection on reset */
// #define	ECONNABORTED	53		/* Software caused connection abort */
// #define	ECONNRESET	54		/* Connection reset by peer */
// #define	ENOBUFS		55		/* No buffer space available */
// #define	EISCONN		56		/* Socket is already connected */
// #define	ENOTCONN	57		/* Socket is not connected */
// #define	ESHUTDOWN	58		/* Can't send after socket shutdown */
// #define	ETOOMANYREFS	59		/* Too many references: can't splice */
// #define	ETIMEDOUT	60		/* Operation timed out */
// #define	ECONNREFUSED	61		/* Connection refused */
//
// #define	ELOOP		62		/* Too many levels of symbolic links */
// #define	ENAMETOOLONG	63		/* File name too long */
//
// /* should be rearranged */
// #define	EHOSTDOWN	64		/* Host is down */
// #define	EHOSTUNREACH	65		/* No route to host */
// #define	ENOTEMPTY	66		/* Directory not empty */
//
// /* quotas & mush */
// #define	EPROCLIM	67		/* Too many processes */
// #define	EUSERS		68		/* Too many users */
// #define	EDQUOT		69		/* Disc quota exceeded */
//
// /* Network File System */
// #define	ESTALE		70		/* Stale NFS file handle */
// #define	EREMOTE		71		/* Too many levels of remote in path */
// #define	EBADRPC		72		/* RPC struct is bad */
// #define	ERPCMISMATCH	73		/* RPC version wrong */
// #define	EPROGUNAVAIL	74		/* RPC prog. not avail */
// #define	EPROGMISMATCH	75		/* Program version wrong */
// #define	EPROCUNAVAIL	76		/* Bad procedure for program */
//
// #define	ENOLCK		77		/* No locks available */
// #define	ENOSYS		78		/* Function not implemented */
//
// #define	EFTYPE		79		/* Inappropriate file type or format */
// #define	EAUTH		80		/* Authentication error */
// #define	ENEEDAUTH	81		/* Need authenticator */
//
// /* SystemV IPC */
// #define	EIDRM		82		/* Identifier removed */
// #define	ENOMSG		83		/* No message of desired type */
// #define	EOVERFLOW	84		/* Value too large to be stored in data type */
//
// /* Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995 */
// #define	EILSEQ		85		/* Illegal byte sequence */
//
// /* From IEEE Std 1003.1-2001 */
// /* Base, Realtime, Threads or Thread Priority Scheduling option errors */
// #define ENOTSUP		86		/* Not supported */
//
// /* Realtime option errors */
// #define ECANCELED	87		/* Operation canceled */
//
// /* Realtime, XSI STREAMS option errors */
// #define EBADMSG		88		/* Bad or Corrupt message */
//
// /* XSI STREAMS option errors  */
// #define ENODATA		89		/* No message available */
// #define ENOSR		90		/* No STREAM resources */
// #define ENOSTR		91		/* Not a STREAM */
// #define ETIME		92		/* STREAM ioctl timeout */
//
// /* File system extended attribute errors */
// #define	ENOATTR		93		/* Attribute not found */
//
// /* Realtime, XSI STREAMS option errors */
// #define	EMULTIHOP	94		/* Multihop attempted */
// #define	ENOLINK		95		/* Link has been severed */
// #define	EPROTO		96		/* Protocol error */
//
// #define	ELAST		96		/* Must equal largest errno */
//
// #if defined(_KERNEL) || defined(_KMEMUSER)
// /* pseudo-errors returned inside kernel to modify return to process */
// #define	EJUSTRETURN	-2		/* don't modify regs, just return */
// #define	ERESTART	-3		/* restart syscall */
// #define	EPASSTHROUGH	-4		/* ioctl not handled by this layer */
// #define	EDUPFD		-5		/* Dup given fd */
// #define	EMOVEFD		-6		/* Move given fd */
// #endif
//
// #endif /* !_SYS_ERRNO_H_ */
