//! Definitions of error codes from NetBSD `errno.h`

use super::c_int;

/// Operation not permitted
pub const EPERM: c_int = 1;

/// No such file or directory
pub const ENOENT: c_int = 2;

/// No such process
pub const ESRCH: c_int = 3;

/// Interrupted system call
pub const EINTR: c_int = 4;

/// Input/output error
pub const EIO: c_int = 5;

/// Device not configured
pub const ENXIO: c_int = 6;

/// Argument list too long
pub const E2BIG: c_int = 7;

/// Exec format error
pub const ENOEXEC: c_int = 8;

/// Bad file descriptor
pub const EBADF: c_int = 9;

/// No child processes
pub const ECHILD: c_int = 10;

/// Resource deadlock avoided
pub const EDEADLK: c_int = 11;

/// Cannot allocate memory
pub const ENOMEM: c_int = 12;

/// Permission denied
pub const EACCES: c_int = 13;

/// Bad address
pub const EFAULT: c_int = 14;

/// Block device required
pub const ENOTBLK: c_int = 15;

/// Device busy
pub const EBUSY: c_int = 16;

/// File exists
pub const EEXIST: c_int = 17;

/// Cross-device link
pub const EXDEV: c_int = 18;

/// Operation not supported by device
pub const ENODEV: c_int = 19;

/// Not a directory
pub const ENOTDIR: c_int = 20;

/// Is a directory
pub const EISDIR: c_int = 21;

/// Invalid argument
pub const EINVAL: c_int = 22;

/// Too many open files in system
pub const ENFILE: c_int = 23;

/// Too many open files
pub const EMFILE: c_int = 24;

/// Inappropriate ioctl for device
pub const ENOTTY: c_int = 25;

/// Text file busy
pub const ETXTBSY: c_int = 26;

/// File too large
pub const EFBIG: c_int = 27;

/// No space left on device
pub const ENOSPC: c_int = 28;

/// Illegal seek
pub const ESPIPE: c_int = 29;

/// Read-only file system
pub const EROFS: c_int = 30;

/// Too many links
pub const EMLINK: c_int = 31;

/// Broken pipe
pub const EPIPE: c_int = 32;

//
// math software
//

/// Numerical argument out of domain
pub const EDOM: c_int = 33;

/// Result too large or too small
pub const ERANGE: c_int = 34;

// non-blocking and interrupt IO

/// Resource temporarily unavailable
pub const EAGAIN: c_int = 35;

/// Operation would block
pub const EWOULDBLOCK: c_int = EAGAIN;

/// Operation now in progress
pub const EINPROGRESS: c_int = 36;

/// Operation already in progress
pub const EALREADY: c_int = 37;

//
// ipc/network software -- argument errors
//

/// Socket operation on non-socket
pub const ENOTSOCK: c_int = 38;

/// Destination address required
pub const EDESTADDRREQ: c_int = 39;

/// Message too long
pub const EMSGSIZE: c_int = 40;

/// Protocol wrong type for socket
pub const EPROTOTYPE: c_int = 41;

/// Protocol option not available
pub const ENOPROTOOPT: c_int = 42;

/// Protocol not supported
pub const EPROTONOSUPPORT: c_int = 43;

/// Socket type not supported
pub const ESOCKTNOSUPPORT: c_int = 44;

/// Operation not supported
pub const EOPNOTSUPP: c_int = 45;

/// Protocol family not supported
pub const EPFNOSUPPORT: c_int = 46;

/// Address family not supported by protocol family
pub const EAFNOSUPPORT: c_int = 47;

/// Address already in use
pub const EADDRINUSE: c_int = 48;

/// Can't assign requested address
pub const EADDRNOTAVAIL: c_int = 49;

//
// ipc/network software -- operational errors
//

/// Network is down
pub const ENETDOWN: c_int = 50;

/// Network is unreachable
pub const ENETUNREACH: c_int = 51;

/// Network dropped connection on reset
pub const ENETRESET: c_int = 52;

/// Software caused connection abort
pub const ECONNABORTED: c_int = 53;

/// Connection reset by peer
pub const ECONNRESET: c_int = 54;

/// No buffer space available
pub const ENOBUFS: c_int = 55;

/// Socket is already connected
pub const EISCONN: c_int = 56;

/// Socket is not connected
pub const ENOTCONN: c_int = 57;

/// Can't send after socket shutdown
pub const ESHUTDOWN: c_int = 58;

/// Too many references: can't splice
pub const ETOOMANYREFS: c_int = 59;

/// Operation timed out
pub const ETIMEDOUT: c_int = 60;

/// Connection refused
pub const ECONNREFUSED: c_int = 61;

/// Too many levels of symbolic links
pub const ELOOP: c_int = 62;

/// File name too long
pub const ENAMETOOLONG: c_int = 63;

/// Host is down
pub const EHOSTDOWN: c_int = 64;

/// No route to host
pub const EHOSTUNREACH: c_int = 65;

/// Directory not empty
pub const ENOTEMPTY: c_int = 66;

//
// quotas & mush
//

/// Too many processes
pub const EPROCLIM: c_int = 67;

/// Too many users
pub const EUSERS: c_int = 68;

/// Disc quota exceeded
pub const EDQUOT: c_int = 69;

//
// Network File System
//

/// Stale NFS file handle
pub const ESTALE: c_int = 70;

/// Too many levels of remote in path
pub const EREMOTE: c_int = 71;

/// RPC struct is bad
pub const EBADRPC: c_int = 72;

/// RPC version wrong
pub const ERPCMISMATCH: c_int = 73;

/// RPC prog. not avail
pub const EPROGUNAVAIL: c_int = 74;

/// Program version wrong
pub const EPROGMISMATCH: c_int = 75;

/// Bad procedure for program
pub const EPROCUNAVAIL: c_int = 76;

/// No locks available
pub const ENOLCK: c_int = 77;

/// Function not implemented
pub const ENOSYS: c_int = 78;

/// Inappropriate file type or format
pub const EFTYPE: c_int = 79;

/// Authentication error
pub const EAUTH: c_int = 80;

/// Need authenticator
pub const ENEEDAUTH: c_int = 81;

//
// SystemV IPC
//

/// Identifier removed
pub const EIDRM: c_int = 82;

/// No message of desired type
pub const ENOMSG: c_int = 83;

/// Value too large to be stored in data type
pub const EOVERFLOW: c_int = 84;

// Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995

/// Illegal byte sequence
pub const EILSEQ: c_int = 85;

//
// From IEEE Std 1003.1-2001
// Base, Realtime, Threads or Thread Priority Scheduling option errors
//

/// Not supported
pub const ENOTSUP: c_int = 86;

//
// Realtime option errors
//

/// Operation canceled
pub const ECANCELED: c_int = 87;

//
// Realtime, XSI STREAMS option errors
//

/// Bad or Corrupt message
pub const EBADMSG: c_int = 88;

// XSI STREAMS option errors

/// No message available
pub const ENODATA: c_int = 89;

/// No STREAM resources
pub const ENOSR: c_int = 90;

/// Not a STREAM
pub const ENOSTR: c_int = 91;

/// STREAM ioctl timeout
pub const ETIME: c_int = 92;

//
// File system extended attribute errors
//

/// Attribute not found
pub const ENOATTR: c_int = 93;

// Realtime, XSI STREAMS option errors

/// Multihop attempted
pub const EMULTIHOP: c_int = 94;

/// Link has been severed
pub const ENOLINK: c_int = 95;

/// Protocol error
pub const EPROTO: c_int = 96;

/// Must equal largest errno
pub const ELAST: c_int = 96;

//
// pseudo-errors returned inside kernel to modify return to process
//

/// don't modify regs, just return
pub const EJUSTRETURN: c_int = 2;

/// restart syscall
pub const ERESTART: c_int = 3;

/// ioctl not handled by this layer
pub const EPASSTHROUGH: c_int = 4;

/// Dup given fd
pub const EDUPFD: c_int = 5;

/// Move given fd
pub const EMOVEFD: c_int = 6;
