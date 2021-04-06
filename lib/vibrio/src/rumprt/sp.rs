// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The sp interface implementation, just stubs at the moment.

use super::{c_int, c_size_t, c_void};

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_anonmmap(
    _arg: *mut c_void,
    _howmuch: c_size_t,
    _addr: *const *const c_void,
) {
    unreachable!("rumpuser_sp_anonmmap");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_copyin(
    _arg: *mut c_void,
    _raddr: *const c_void,
    _laddr: *mut c_void,
    _len: c_size_t,
) {
    unreachable!("rumpuser_sp_copyin");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_copyinstr(
    _arg: *mut c_void,
    _raddr: *const c_void,
    _laddr: *mut c_void,
    _dlen: *mut c_size_t,
) {
    unreachable!("rumpuser_sp_copyinstr");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_copyout(
    _arg: *mut c_void,
    _laddr: *const c_void,
    _raddr: *mut c_void,
    _dlen: c_size_t,
) {
    unreachable!("rumpuser_sp_copyout");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_copyoutstr(
    _arg: *mut c_void,
    _laddr: *const c_void,
    _raddr: *mut c_void,
    _dlen: *const c_size_t,
) {
    unreachable!("rumpuser_sp_copyoutstr");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_fini(_arg: *mut c_void) {
    unreachable!("rumpuser_sp_fini");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_init(
    _url: *const char,
    _ostype: *const char,
    _osrelease: *const char,
    _machine: *const char,
) {
    unreachable!("rumpuser_sp_init");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_sp_raise(_arg: *mut c_void, _signo: c_int) {
    unreachable!("rumpuser_sp_raise");
}
