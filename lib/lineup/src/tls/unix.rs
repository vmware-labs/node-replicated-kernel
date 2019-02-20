use crate::tls::ThreadLocalStorage;
use core::mem::transmute;
use core::ptr;

// silly, broken TLS storage for now:
static mut TLS: *mut ThreadLocalStorage = ptr::null_mut();

pub(crate) unsafe fn get_tls<'a>() -> *mut ThreadLocalStorage<'a> {
    transmute::<*mut ThreadLocalStorage<'static>, *mut ThreadLocalStorage<'a>>(TLS)
}

pub(crate) unsafe fn set_tls<'a>(t: *mut ThreadLocalStorage<'a>) {
    TLS = transmute::<*mut ThreadLocalStorage<'a>, *mut ThreadLocalStorage<'static>>(t);
}
