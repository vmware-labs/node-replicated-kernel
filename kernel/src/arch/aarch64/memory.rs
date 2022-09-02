// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use armv8::aarch64::vm::granule4k::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

// Re-export from the x86 crate
pub use kpi::{MemType, KERNEL_BASE};

/// Translate a kernel 'virtual' address to the physical address of the memory.
pub(crate) fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    let vaddr_val: usize = v.into();
    PAddr::from(vaddr_val as u64 - KERNEL_BASE)
}

/// Translate a physical memory address into a kernel addressable location.
pub(crate) fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    let paddr_val: u64 = p.into();
    VAddr::from((paddr_val + KERNEL_BASE) as usize)
}
