//! Functions to manage thread-local storage.

use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;

use log::info;

/// ELF TLS sections start and ends
extern "C" {
    static _tdata_start: u8;
    static _tdata_end: u8;
    static _tbss_start: u8;
    static _tbss_end: u8;
}

#[no_mangle]
pub unsafe extern "C" fn __libc_static_tls_setup() { /* NOP */
}

#[no_mangle]
pub unsafe extern "C" fn _rtld_tls_allocate() -> *mut u8 {
    initialize_tls()
}

#[no_mangle]
pub unsafe extern "C" fn _rtld_tls_free(tls_ptr: *mut u8) {
    let (data_len, bss_len, internal_len) = calculate_tls_size();
    let tls_buffer_len = data_len + bss_len + internal_len;
    let layout = Layout::from_size_align_unchecked(tls_buffer_len, 8);

    dealloc(tls_ptr, layout)
}

/// Determines the necessary space for per-thread TLS memory regions.
///
/// Total required bytes is the sum of the `tdata`, `tbss`,
/// and a statically defined extra section.
/// (i.e., the sum of all return values)
fn calculate_tls_size() -> (usize, usize, usize) {
    let (tdata_size, tbss_size) = unsafe {
        let tdata_start_ptr = &_tdata_start as *const u8;
        let tdata_end_ptr = &_tdata_end as *const u8;
        let tbss_start_ptr = &_tbss_start as *const u8;
        let tbss_end_ptr = &_tbss_end as *const u8;

        (
            tdata_start_ptr.offset_from(tdata_end_ptr),
            tbss_start_ptr.offset_from(tbss_end_ptr),
        )
    };

    // TODO(document) Magic from rumprun:
    let tls_extra = 8 * 6usize;

    info!(
        "tls area size is: data + bss + extra = {}",
        tdata_size + tbss_size + tls_extra as isize
    );
    (tdata_size as usize, tbss_size as usize, tls_extra)
}

/// Allocate buffer space (as a Vec) for TLS, initialize it properly.
pub unsafe fn initialize_tls() -> *mut u8 {
    let (data_len, bss_len, internal_len) = calculate_tls_size();
    let tls_buffer_len = data_len + bss_len + internal_len;
    let tls_space: *mut u8 = alloc_zeroed(Layout::from_size_align_unchecked(tls_buffer_len, 8));

    let tdata_start_ptr = &_tdata_start as *const u8;
    assert!(tls_buffer_len - 16 >= data_len);
    core::ptr::copy_nonoverlapping(tdata_start_ptr, tls_space.offset(16), data_len);

    tls_space
}
