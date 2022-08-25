// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Try to retrieve the per-core memory allocator by reading the gs register.
///
/// This may return None if the memory allocators is not yet set (i.e., during
/// initialization).
///
/// # Safety
/// - The fsgsbase bit must be enabled.
/// - This gets a handle to PerCoreMemory (ideally, we should ensure that there
///   is no outstanding mut alias to it e.g., during initialization see comments
///   in mod.rs)
pub(crate) fn try_per_core_mem() -> Option<&'static PerCoreMemory> {
    panic!("not yet implemented");
}

/// Reference to per-core memory state.
///
/// Must only call this after initialization has completed. So basically ok to
/// call in everywhere in the kernel except care must be taken in `arch`,
/// `crate::memory` and some places in `arch::irq`.
///
/// # Panics
/// - If the per-core memory is not yet initialized (only in debug mode).
pub(crate) fn per_core_mem() -> &'static PerCoreMemory {
    panic!("not yet implemented");
}
