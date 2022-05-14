// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

use crate::stack::Stack;

/// Starts up the core identified by `core_id`, after initialization it begins
/// to executing in `init_function` and uses `stack` as a stack.
///
/// # Safety
/// This is likely to be pretty safe on `unix` but not so much on bare-metal
/// hardware.
pub unsafe fn initialize<A>(
    _core_id: x86::apic::ApicId,
    _init_function: fn(Arc<A>, &AtomicBool),
    _args: Arc<A>,
    _initialized: &AtomicBool,
    _stack: &dyn Stack,
) {
    unimplemented!("initialize is not implemented");
}
