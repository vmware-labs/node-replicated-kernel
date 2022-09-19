// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A trait defining architecture independent address spaces.

use core::cmp::PartialEq;
use core::fmt;

use crate::error::KError;
use bit_field::BitField;

use super::{Frame, PAddr, VAddr};

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TlbFlushHandle {
    pub vaddr: VAddr,
    pub frame: Frame,
    pub core_map: CoreBitMap,
}

impl TlbFlushHandle {
    pub(crate) fn new(vaddr: VAddr, frame: Frame) -> TlbFlushHandle {
        TlbFlushHandle {
            vaddr,
            frame,
            core_map: Default::default(),
        }
    }

    pub(crate) fn add_core(&mut self, gtid: atopology::GlobalThreadId) {
        self.core_map.set_bit(gtid as usize, true)
    }

    pub(crate) fn cores(&self) -> CoreBitMapIter {
        CoreBitMapIter(self.core_map)
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct CoreBitMap {
    pub low: u128,
    pub high: u128,
}
// Who needs more than 256 cores anyways?
static_assertions::const_assert!(crate::arch::MAX_CORES < (u128::BITS as usize) * 2);

impl CoreBitMap {
    pub(crate) fn set_bit(&mut self, bit: usize, value: bool) {
        if bit <= 127 {
            self.low.set_bit(bit, value);
        } else {
            let bit = bit - 128;
            self.high.set_bit(bit, value);
        }
    }
}

pub(crate) struct CoreBitMapIter(CoreBitMap);

impl Iterator for CoreBitMapIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.low == 0u128 && self.0.high == 0u128 {
            None
        } else if self.0.low > 0u128 {
            let least_significant_bit_pos = self.0.low.trailing_zeros() as usize;
            let least_significant_bit = self.0.low & self.0.low.wrapping_neg();
            self.0.low ^= least_significant_bit;
            Some(least_significant_bit_pos)
        } else {
            debug_assert!(self.0.high > 0);
            let least_significant_bit_pos = self.0.high.trailing_zeros() as usize;
            let least_significant_bit = self.0.high & self.0.high.wrapping_neg();
            self.0.high ^= least_significant_bit;
            Some(u128::BITS as usize + least_significant_bit_pos)
        }
    }
}

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
#[derive(Debug, PartialEq)]
pub(crate) enum MappingType {
    _ElfText,
    _ElfData,
    _Executor,
    Heap,
}

pub(crate) struct MappingInfo {
    pub frame: Frame,
    pub rights: MapAction,
    pub typ: MappingType,
}

impl MappingInfo {
    pub(crate) fn new(frame: Frame, rights: MapAction) -> Self {
        MappingInfo {
            frame,
            rights,
            typ: MappingType::Heap,
        }
    }

    /// Return range of the region if it would start at `base`
    pub(crate) fn vrange(&self, base: VAddr) -> core::ops::Range<usize> {
        base.as_usize()..base.as_usize() + self.frame.size
    }
}

impl fmt::Debug for MappingInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappingInfo")
            .field("frame", &self.frame)
            .field("rights", &self.rights)
            .field("typ", &self.typ)
            .finish()
    }
}

/// Generic address space functionality.
pub(crate) trait AddressSpace {
    /// Maps a list of `frames` at `base` in the address space
    /// with the access rights defined by `action`.
    fn map_frames(&mut self, base: VAddr, frames: &[(Frame, MapAction)]) -> Result<(), KError> {
        let mut cur_base = base;
        for (frame, action) in frames {
            self.map_frame(cur_base, *frame, *action)?;
            cur_base = VAddr::from(cur_base.as_usize().checked_add(frame.size()).ok_or(
                KError::BaseOverflow {
                    base: base.as_u64(),
                },
            )?);
        }

        Ok(())
    }

    /// Maps the given `frame` at `base` in the address space
    /// with the access rights defined by `action`.
    ///
    /// Will return an error if new mapping overlaps with
    /// something already mapped.
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError>;

    /// Estimates how many base-pages are needed (for page-tables)
    /// to map the given list of frames in the address space starting at `base`.
    ///
    /// This can be used to make sure the `pager` in `map_frame(s)` is refilled
    /// before invoking map calls.
    fn map_memory_requirements(base: VAddr, frames: &[Frame]) -> usize;

    /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    ///
    /// # Returns
    /// The range (vregion) that was adjusted if successfull.
    fn adjust(&mut self, vaddr: VAddr, rights: MapAction) -> Result<(VAddr, usize), KError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), KError>;

    /// Removes the frame from the address space that contains `vaddr`.
    ///
    /// # Returns
    /// The frame to the caller along with a `TlbFlushHandle` that may have to be
    /// invoked to flush the TLB.
    fn unmap(&mut self, vaddr: VAddr) -> Result<TlbFlushHandle, KError>;

    // Returns an iterator of all currently mapped memory regions.
    //fn mappings()
}

/// Mapping rights to give to address translation.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(unused)]
pub(crate) enum MapAction {
    /// Don't map
    None,
    /// Map region read-only.
    ReadUser,
    /// Map region read-only for kernel.
    ReadKernel,
    /// Map region read-write.
    ReadWriteUser,
    /// Map region read-write, disable page-cache for IO regions.
    ReadWriteUserNoCache,
    /// Map region read-write for kernel.
    ReadWriteKernel,
    /// Map region read-executable.
    ReadExecuteUser,
    /// Map region read-executable for kernel.
    ReadExecuteKernel,
    /// Map region read-write-executable.
    ReadWriteExecuteUser,
    /// Map region read-write-executable for kernel.
    ReadWriteExecuteKernel,
}

impl MapAction {
    pub(crate) fn is_kernel(&self) -> bool {
        match self {
            MapAction::ReadKernel
            | MapAction::ReadWriteKernel
            | MapAction::ReadExecuteKernel
            | MapAction::ReadWriteExecuteKernel => true,
            _ => false,
        }
    }

    pub(crate) fn is_readable(&self) -> bool {
        *self != MapAction::None
    }

    pub(crate) fn is_writable(&self) -> bool {
        use MapAction::*;
        matches!(
            self,
            ReadWriteUser
                | ReadWriteUserNoCache
                | ReadWriteKernel
                | ReadWriteExecuteUser
                | ReadWriteExecuteKernel
        )
    }

    pub(crate) fn is_executable(&self) -> bool {
        use MapAction::*;
        matches!(
            self,
            ReadExecuteUser | ReadExecuteKernel | ReadWriteExecuteUser | ReadWriteExecuteKernel
        )
    }
}

impl fmt::Display for MapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use MapAction::*;
        match self {
            None => write!(f, " ---"),
            ReadUser => write!(f, "uR--"),
            ReadKernel => write!(f, "kR--"),
            ReadWriteUser => write!(f, "uRW-"),
            ReadWriteUserNoCache => write!(f, "uRW-IO"),
            ReadWriteKernel => write!(f, "kRW-"),
            ReadExecuteUser => write!(f, "uR-X"),
            ReadExecuteKernel => write!(f, "kR-X"),
            ReadWriteExecuteUser => write!(f, "uRWX"),
            ReadWriteExecuteKernel => write!(f, "kRWX"),
        }
    }
}
