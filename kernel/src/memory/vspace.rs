// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A trait defining architecture independent address spaces.

use core::cmp::PartialEq;
use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use kpi::system::MachineThreadId;

use crate::error::KError;
use bit_field::BitField;

use super::{Frame, PAddr, VAddr};

/// A handle we use to flush specific TLB entries.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TlbFlushHandle {
    /// Virtual address of the mapping to flush.
    pub vaddr: VAddr,
    /// It pointed to this PAddr before removal.
    pub paddr: PAddr,
    /// The removed size of the mapping was this many bytes.
    pub size: usize,
    /// The mapping had those flags.
    pub flags: MapAction,
    /// The mapping may be cached in the TLB on the cores following cores.
    ///
    /// Note this is initialized to the correct values only later, after the
    /// `Self` is created and remains empty at first.
    pub core_map: CoreBitMap,
}

impl TlbFlushHandle {
    pub(crate) fn new(vaddr: VAddr, paddr: PAddr, size: usize, flags: MapAction) -> TlbFlushHandle {
        TlbFlushHandle {
            vaddr,
            paddr,
            size,
            flags,
            core_map: Default::default(),
        }
    }

    pub(crate) fn add_core(&mut self, mtid: MachineThreadId) {
        self.core_map.set_bit(mtid, true)
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

    #[allow(unused)]
    pub(crate) fn is_empty(&self) -> bool {
        self.low == 0u128 && self.high == 0u128
    }
}

pub(crate) struct CoreBitMapIter(pub(crate) CoreBitMap);

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

/// Mapping meta-data and permissions for an address translation.
///
/// - Just a bunch of boolean flags.
/// - `is_writeable()` implies `is_readable()`
/// - Permissions/flags can be combined using bit-wise OR.
///
/// ```text
///                no-perm   is_readable:           is_writeable:        is_executable:
/// ------------------------------------------------------------------------------------------
/// user-space   | none()  | all except aliased() | write()            | execute()
///              |         | and not kernel()     |                    |
/// ------------------------------------------------------------------------------------------
/// kernel-space | none()  | kernel()             | kernel() + write() | kernel() + execute()
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(unused)]
pub(crate) struct MapAction {
    /// The mapping is readable if present.
    present: bool,
    /// It's a mapping with write access.
    write: bool,
    /// It's a mapping that the CPU can execute code from.
    exec: bool,
    /// It's a mapping that is accessible in kernel-space (and implicitly not in
    /// user-space).
    kernel: bool,
    /// Writes to this regions are not cached.
    not_cached: bool,
    /// It's a mapping that (maybe) has asliases (e.g., the physical address
    /// might be mapped multiple times (in the same address space) at different
    /// virtual offsets).
    ///
    /// This is possible with the `map_frame_id` API variants and we have to
    /// track it so we unly free the frame once all aliases are unmapped again.
    aliased: bool,
}

impl MapAction {
    /// A non-existent mapping.
    pub(crate) const fn none() -> Self {
        MapAction {
            present: false,
            write: false,
            exec: false,
            kernel: false,
            not_cached: false,
            aliased: false,
        }
    }

    /// A readable mapping that is readable (in user-space).
    pub(crate) const fn user() -> Self {
        MapAction {
            present: true,
            write: false,
            exec: false,
            kernel: false,
            not_cached: false,
            aliased: false,
        }
    }

    /// A readable mapping that is accessible in kernel-space.
    pub(crate) const fn kernel() -> Self {
        MapAction {
            present: true,
            write: false,
            exec: false,
            kernel: true,
            not_cached: false,
            aliased: false,
        }
    }

    /// A mapping that writeable and readable (in user-space).
    pub(crate) const fn write() -> Self {
        MapAction {
            present: true,
            write: true,
            exec: false,
            kernel: false,
            not_cached: false,
            aliased: false,
        }
    }

    /// A mapping that the CPU can execute code from.
    pub(crate) const fn execute() -> Self {
        MapAction {
            present: true,
            write: false,
            exec: true,
            kernel: false,
            not_cached: false,
            aliased: false,
        }
    }

    /// A mapping for memory that isn't cacheable.
    pub(crate) const fn no_cache() -> Self {
        MapAction {
            present: true,
            write: false,
            exec: false,
            kernel: false,
            not_cached: true,
            aliased: false,
        }
    }

    /// A mapping that is potentially aliased.
    #[allow(unused)]
    pub(crate) const fn aliased() -> Self {
        MapAction {
            present: false,
            write: false,
            exec: false,
            kernel: false,
            not_cached: false,
            aliased: true,
        }
    }

    /// Is this memory read-able?
    pub(crate) fn is_readable(&self) -> bool {
        self.present
    }

    /// Is this memory write-able?
    pub(crate) fn is_writable(&self) -> bool {
        self.write
    }

    /// Is this memory execut-able?
    pub(crate) fn is_executable(&self) -> bool {
        self.exec
    }

    /// Is this memory cache-able?
    #[allow(unused)]
    pub(crate) fn is_cacheable(&self) -> bool {
        !self.not_cached
    }

    /// Does this mapping (potentially) have aliases in the address space?
    pub(crate) fn is_aliasable(&self) -> bool {
        self.aliased
    }

    /// Is this user-space memory?
    pub(crate) fn is_userspace(&self) -> bool {
        !self.kernel
    }

    /// Is this kernel-space memory?
    pub(crate) fn is_kernelspace(&self) -> bool {
        self.kernel
    }
}

impl fmt::Display for MapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let MapAction {
            present,
            write,
            exec,
            kernel,
            not_cached,
            aliased,
        } = *self;

        let present = if present { 'p' } else { '-' };
        let kernel_user = if kernel { 'k' } else { 'u' };
        let read_write = if write { "rw" } else { "r" };
        let exec = if exec { "x" } else { "-" };
        let not_cached = if not_cached { "[nc]" } else { "-" };
        let aliased = if aliased { "[al]" } else { "-" };

        write!(
            f,
            "{}{}{}{}{}{}",
            kernel_user, present, read_write, exec, not_cached, aliased
        )
    }
}

impl BitOr for MapAction {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            present: self.present || rhs.present,
            write: self.write || rhs.write,
            exec: self.exec || rhs.exec,
            kernel: self.kernel || rhs.kernel,
            not_cached: self.not_cached || rhs.not_cached,
            aliased: self.aliased || rhs.aliased,
        }
    }
}

impl BitOrAssign for MapAction {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}
