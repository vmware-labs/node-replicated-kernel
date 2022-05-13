// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Functionality to boot application cores on x86.
//!
//! This code is closely intertwingled with the assembly code in `start_ap.S`,
//! make sure these two files are and stay in sync.

use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

use crate::stack::Stack;

/// Starts up the core identified by `core_id`, after initialization it begins
/// to executing in `init_function` and uses `stack` as a stack.
pub unsafe fn initialize<A>(
    _core_id: x86::apic::ApicId,
    _init_function: fn(Arc<A>, &AtomicBool),
    _args: Arc<A>,
    _initialized: &AtomicBool,
    _stack: &dyn Stack,
) {
    unimplemented!("initialize is not implemented");
}
