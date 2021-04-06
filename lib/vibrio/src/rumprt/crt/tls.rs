// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Functions to manage thread-local storage.
//!
//! In our case this is already managed by lineup.

#[no_mangle]
pub unsafe extern "C" fn __libc_static_tls_setup() {
    /* NOP */
}

#[no_mangle]
pub unsafe extern "C" fn _rtld_tls_allocate() -> *mut u8 {
    unsafe { lineup::tls2::ThreadControlBlock::new_tls_area() as *mut u8 }
}

#[no_mangle]
pub unsafe extern "C" fn _rtld_tls_free(tls_ptr: *mut u8) {
    /* NOP */
    unreachable!()
}
