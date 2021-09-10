// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Abstraction for system calls to do memory management operations.

use core::convert::TryInto;

use crate::process::FrameId;
use crate::*;

use crate::syscall;

use x86::bits64::paging::{PAddr, VAddr};

/// System calls to manipulate the process' address-space.
pub struct VSpace;

impl VSpace {
    /// Back a region of memory with DRAM.
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn map(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::Map, base, bound)
    }

    /// Unmap region of virtual memory.
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn unmap(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::Unmap, base, bound)
    }

    /// Back a region of memory with PMEM.
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn map_pmem(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::MapPM, base, bound)
    }

    /// Unmap region of virtual memory.
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn unmap_pmem(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::UnmapPM, base, bound)
    }

    /// Maps device memory (identity mapped with physical mem).
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn map_device(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::MapDevice, base, bound)
    }

    /// Maps a registered frame.
    ///
    /// # Safety
    /// Manipulates address space of process.
    pub unsafe fn map_frame(
        frame_id: FrameId,
        base: u64,
    ) -> Result<(VAddr, PAddr), SystemCallError> {
        let frame_id: u64 = frame_id.try_into().unwrap();
        let (err, paddr, _size) = syscall!(
            SystemCall::VSpace as u64,
            VSpaceOperation::MapFrame as u64,
            base,
            frame_id,
            3
        );

        if err == 0 {
            Ok((VAddr::from(base), PAddr::from(paddr)))
        } else {
            Err(SystemCallError::from(err))
        }
    }

    pub fn identify(base: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        unsafe { VSpace::vspace(VSpaceOperation::Identify, base, 0) }
    }

    /// Manipulate the virtual address space.
    unsafe fn vspace(
        op: VSpaceOperation,
        base: u64,
        bound: u64,
    ) -> Result<(VAddr, PAddr), SystemCallError> {
        let (err, paddr, size) = syscall!(SystemCall::VSpace as u64, op as u64, base, bound, 3);

        log::trace!(
            "OP={:?} {:#x} -- {:#x} --> {:#x} -- {:#x}",
            op,
            base,
            base + bound,
            paddr,
            paddr + bound,
        );

        if err == 0 {
            debug_assert_eq!(
                bound, size,
                "VSpace Map should return mapped region size as 2nd argument"
            );
            Ok((VAddr::from(base), PAddr::from(paddr)))
        } else {
            Err(SystemCallError::from(err))
        }
    }
}

/// System call to manage physical memory of a process.
pub struct PhysicalMemory;

impl PhysicalMemory {
    pub fn allocate_base_page() -> Result<(FrameId, PAddr), SystemCallError> {
        unsafe {
            let (err, frame_id, paddr) = syscall!(
                SystemCall::Process as u64,
                ProcessOperation::AllocatePhysical as u64,
                x86::current::paging::BASE_PAGE_SIZE,
                3
            );

            if err == 0 {
                debug_assert!(paddr > 0, "Valid PAddr");
                Ok((frame_id.try_into().unwrap(), PAddr::from(paddr)))
            } else {
                Err(SystemCallError::from(err))
            }
        }
    }

    pub fn allocate_large_page() -> Result<(FrameId, PAddr), SystemCallError> {
        unimplemented!()
    }

    pub fn release_base_page(_id: FrameId) -> Result<(), SystemCallError> {
        unimplemented!()
    }

    pub fn release_large_page(_id: FrameId) -> Result<(), SystemCallError> {
        unimplemented!()
    }
}
