// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime support for error handling (i.e., retrieve errno).

use crate::rumprt::c_int;
use lineup::tls2::Environment;

/// Retrieves a mutable pointer to set the current _errno.
///
/// # TODO
/// This should probably be thread safe?
#[no_mangle]
pub unsafe extern "C" fn __errno() -> *mut c_int {
    &mut Environment::thread().errno as *mut c_int
}
