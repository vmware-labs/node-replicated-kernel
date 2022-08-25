// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! AArch64 specific kernel code.

pub use bootloader_shared::*;

pub mod debug;
pub mod kcb;
pub mod memory;
pub mod process;

pub(crate) const MAX_NUMA_NODES: usize = 12;
pub(crate) const MAX_CORES: usize = 192;

/// Goes to sleep / halts the core.
///
/// Interrupts are enabled before going to sleep.
pub(crate) fn halt() -> ! {
    unsafe {
        asm!("wfi" :::: "volatile");
    }
}

/// For cores that advances the replica eagerly. This avoids additional IPI costs.
pub(crate) fn advance_fs_replica() {
    panic!("not yet implemented");
}
