// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A trait defining architecture independent address spaces.

use core::cmp::PartialEq;
use core::fmt;

use crate::error::KError;
use bit_field::BitField;
use x86::current::paging::{PDFlags, PDPTFlags, PTFlags};

use super::{Frame, PAddr, VAddr};

#[derive(Debug, PartialEq, Clone)]
pub struct TlbFlushHandle {
    pub vaddr: VAddr,
    pub frame: Frame,
    pub core_map: CoreBitMap,
}

impl TlbFlushHandle {
    pub fn new(vaddr: VAddr, frame: Frame) -> TlbFlushHandle {
        TlbFlushHandle {
            vaddr,
            frame,
            core_map: Default::default(),
        }
    }

    pub fn add_core(&mut self, gtid: atopology::GlobalThreadId) {
        self.core_map.set_bit(gtid as usize, true)
    }

    pub fn cores(&self) -> CoreBitMapIter {
        CoreBitMapIter(self.core_map)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CoreBitMap {
    pub low: u128,
    pub high: u128,
}
// Who needs more than 256 cores anyways?
static_assertions::const_assert!(crate::arch::MAX_CORES < (u128::BITS as usize) * 2);

impl Default for CoreBitMap {
    fn default() -> Self {
        CoreBitMap { low: 0, high: 0 }
    }
}

impl CoreBitMap {
    pub fn set_bit(&mut self, bit: usize, value: bool) {
        if bit <= 127 {
            self.low.set_bit(bit, value);
        } else {
            let bit = bit - 128;
            self.high.set_bit(bit, value);
        }
    }
}

pub struct CoreBitMapIter(CoreBitMap);

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
pub enum MappingType {
    _ElfText,
    _ElfData,
    _Executor,
    Heap,
}

pub struct MappingInfo {
    pub frame: Frame,
    pub rights: MapAction,
    pub typ: MappingType,
}

impl MappingInfo {
    pub fn new(frame: Frame, rights: MapAction) -> Self {
        MappingInfo {
            frame,
            rights,
            typ: MappingType::Heap,
        }
    }

    /// Return range of the region if it would start at `base`
    pub fn vrange(&self, base: VAddr) -> core::ops::Range<usize> {
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
pub trait AddressSpace {
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
pub enum MapAction {
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
    /// Transform MapAction into rights for 1 GiB page.
    pub fn to_pdpt_rights(self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD | PDPTFlags::US,
            ReadKernel => PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteUserNoCache => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::US,
            ReadExecuteKernel => PDPTFlags::empty(),
            ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
            ReadWriteExecuteKernel => PDPTFlags::RW,
        }
    }

    pub fn is_readable(&self) -> bool {
        *self != MapAction::None
    }

    pub fn is_writable(&self) -> bool {
        use MapAction::*;
        match self {
            ReadWriteUser => true,
            ReadWriteUserNoCache => true,
            ReadWriteKernel => true,
            ReadWriteExecuteUser => true,
            ReadWriteExecuteKernel => true,
            _ => false,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    pub fn to_pd_rights(self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD | PDFlags::US,
            ReadKernel => PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteUserNoCache => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteKernel => PDFlags::RW | PDFlags::XD,
            ReadExecuteUser => PDFlags::US,
            ReadExecuteKernel => PDFlags::empty(),
            ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
            ReadWriteExecuteKernel => PDFlags::RW,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    pub fn to_pt_rights(self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD | PTFlags::US,
            ReadKernel => PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteUserNoCache => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteKernel => PTFlags::RW | PTFlags::XD,
            ReadExecuteUser => PTFlags::US,
            ReadExecuteKernel => PTFlags::empty(),
            ReadWriteExecuteUser => PTFlags::RW | PTFlags::US,
            ReadWriteExecuteKernel => PTFlags::RW,
        }
    }
}

impl From<PTFlags> for MapAction {
    fn from(f: PTFlags) -> MapAction {
        use MapAction::*;
        let irrelevant_bits: PTFlags =
            PTFlags::PWT | PTFlags::A | PTFlags::D | PTFlags::G | PTFlags::PWT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PTFlags::P | PTFlags::US | PTFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PTFlags::XD | PTFlags::P {
            MapAction::ReadKernel
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::US | PTFlags::P | PTFlags::PCD {
            ReadWriteUserNoCache
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::US | PTFlags::P {
            ReadWriteUser
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::P {
            ReadWriteKernel
        } else if cleaned == PTFlags::US | PTFlags::P {
            ReadExecuteUser
        } else if cleaned == PTFlags::RW | PTFlags::US | PTFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PTFlags::RW | PTFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PTFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
    }
}

impl From<PDFlags> for MapAction {
    fn from(f: PDFlags) -> MapAction {
        use MapAction::*;

        let irrelevant_bits =
            PDFlags::PWT | PDFlags::A | PDFlags::D | PDFlags::PS | PDFlags::G | PDFlags::PAT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PDFlags::P | PDFlags::US | PDFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PDFlags::XD | PDFlags::P {
            MapAction::ReadKernel
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::US | PDFlags::P | PDFlags::PCD {
            ReadWriteUserNoCache
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::US | PDFlags::P {
            ReadWriteUser
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::P {
            ReadWriteKernel
        } else if cleaned == PDFlags::US | PDFlags::P {
            ReadExecuteUser
        } else if cleaned == PDFlags::RW | PDFlags::US | PDFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PDFlags::RW | PDFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PDFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
    }
}

impl From<PDPTFlags> for MapAction {
    fn from(f: PDPTFlags) -> MapAction {
        use MapAction::*;

        let irrelevant_bits: PDPTFlags = PDPTFlags::PWT
            | PDPTFlags::A
            | PDPTFlags::D
            | PDPTFlags::PS
            | PDPTFlags::G
            | PDPTFlags::PAT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PDPTFlags::P | PDPTFlags::US | PDPTFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PDPTFlags::XD | PDPTFlags::P {
            MapAction::ReadKernel
        } else if cleaned
            == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US | PDPTFlags::P | PDPTFlags::PCD
        {
            ReadWriteUserNoCache
        } else if cleaned == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US | PDPTFlags::P {
            ReadWriteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::P {
            ReadWriteKernel
        } else if cleaned == PDPTFlags::US | PDPTFlags::P {
            ReadExecuteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::US | PDPTFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PDPTFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
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
