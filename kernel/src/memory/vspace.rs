//! An trait defining architecture specific address spaces.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::PartialEq;
use core::fmt;

use custom_error::custom_error;
use kpi::SystemCallError;
use x86::current::paging::{PDFlags, PDPTFlags, PTFlags};

use super::{Frame, PAddr, PhysicalPageProvider, VAddr};

#[derive(Debug, PartialEq)]
pub struct TlbFlushHandle {}

impl Default for TlbFlushHandle {
    fn default() -> TlbFlushHandle {
        TlbFlushHandle {}
    }
}

/// Generic address space functionality.
pub trait AddressSpace {
    /// Maps a list of `frames` at `base` in the address space
    /// with the access rights defined by `action`.
    fn map_frames(
        &mut self,
        base: VAddr,
        frames: Vec<(Frame, MapAction)>,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let mut cur_base = base;
        for (frame, action) in frames.into_iter() {
            self.map_frame(cur_base, frame, action, pager)?;
            cur_base = VAddr::from(cur_base.as_usize().checked_add(frame.size()).ok_or(
                AddressSpaceError::BaseOverflow {
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
    fn map_frame(
        &mut self,
        base: VAddr,
        frame: Frame,
        action: MapAction,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError>;

    /// Estimates how many base-pages are needed (for page-tables)
    /// to map the given list of frames in the address space starting at `base`.
    ///
    /// This can be used to make sure the `pager` in `map_frame(s)` is refilled
    /// before invoking map calls.
    fn map_memory_requirements(base: VAddr, frames: &[Frame]) -> usize;

    /// Changes the rights of frames for the region
    /// given by [`base`, `base` + `length`) to `rights`.
    ///
    /// # Returns
    /// How many pages were adjusted if successful.
    fn adjust(
        &mut self,
        base: VAddr,
        length: usize,
        rights: MapAction,
    ) -> Result<usize, AddressSpaceError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError>;

    /// Removes the frame mapped at `base` from the address space.
    ///
    /// # Arguments
    ///  - `base` - should be at the start virtual address of the to be unmapped frame.
    ///
    /// # Returns
    /// The frame to the caller along with a `TlbFlushHandle` that may have to be
    /// invoked to flush the TLB.
    fn unmap(&mut self, base: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError>;

    // Returns an iterator of all currently mapped memory regions.
    //fn mappings()
}

custom_error! {
#[derive(PartialEq)]
pub AddressSpaceError
    InvalidFrame = "Supplied frame was invalid",
    AlreadyMapped = "Address space operation covers existing mapping",
    BaseOverflow{base: u64} = "Provided virtual base was invalid (led to overflow on mappings).",
    NotMapped = "The requested mapping was not found",
    InvalidLength = "The supplied length was invalid",
}

impl Into<SystemCallError> for AddressSpaceError {
    fn into(self) -> SystemCallError {
        match self {
            AddressSpaceError::InvalidFrame => SystemCallError::InternalError,
            AddressSpaceError::AlreadyMapped => SystemCallError::InternalError,
            AddressSpaceError::BaseOverflow { base: _ } => SystemCallError::InternalError,
            AddressSpaceError::NotMapped => SystemCallError::InternalError,
            AddressSpaceError::InvalidLength => SystemCallError::InternalError,
        }
    }
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
    pub fn to_pdpt_rights(&self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD | PDPTFlags::US,
            ReadKernel => PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::US,
            ReadExecuteKernel => PDPTFlags::empty(),
            ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
            ReadWriteExecuteKernel => PDPTFlags::RW,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    pub fn to_pd_rights(&self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD | PDFlags::US,
            ReadKernel => PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteKernel => PDFlags::RW | PDFlags::XD,
            ReadExecuteUser => PDFlags::US,
            ReadExecuteKernel => PDFlags::empty(),
            ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
            ReadWriteExecuteKernel => PDFlags::RW,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    pub fn to_pt_rights(&self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD | PTFlags::US,
            ReadKernel => PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
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
            PTFlags::PWT | PTFlags::PCD | PTFlags::A | PTFlags::D | PTFlags::G | PTFlags::PWT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PTFlags::P | PTFlags::US | PTFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PTFlags::XD | PTFlags::P {
            MapAction::ReadKernel
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

        let irrelevant_bits = PDFlags::PWT
            | PDFlags::PCD
            | PDFlags::A
            | PDFlags::D
            | PDFlags::PS
            | PDFlags::G
            | PDFlags::PAT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PDFlags::P | PDFlags::US | PDFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PDFlags::XD | PDFlags::P {
            MapAction::ReadKernel
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
            | PDPTFlags::PCD
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
            ReadWriteKernel => write!(f, "kRW-"),
            ReadExecuteUser => write!(f, "uR-X"),
            ReadExecuteKernel => write!(f, "kR-X"),
            ReadWriteExecuteUser => write!(f, "uRWX"),
            ReadWriteExecuteKernel => write!(f, "kRWX"),
        }
    }
}

/// Type of resource we're trying to allocate
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResourceType {
    /// Physical memory
    Memory,
}

/// Implementation of a model vspace (for testing)
#[cfg(test)]
pub(crate) mod model {
    use super::*;
    use crate::memory::tcache::TCache;
    use alloc::collections::BTreeMap;
    use core::iter::Iterator;
    use core::ops::Range;

    /// A simple model address space
    ///
    /// Can be used by property testing to see if a hardware address space
    /// implementation is equivalent.
    pub(crate) struct ModelAddressSpace {
        /// The btree maps virtual base addresses to the underlying physical mapping
        /// (ideally the key would be Range<usize> but Range does not implement Ord)
        mappings: BTreeMap<usize, (Frame, MapAction)>,
    }

    impl Default for ModelAddressSpace {
        fn default() -> ModelAddressSpace {
            ModelAddressSpace {
                mappings: BTreeMap::new(),
            }
        }
    }

    impl AddressSpace for ModelAddressSpace {
        fn map_frame(
            &mut self,
            base: VAddr,
            frame: Frame,
            action: MapAction,
            pager: &mut dyn PhysicalPageProvider,
        ) -> Result<(), AddressSpaceError> {
            if frame.size() == 0 {
                return Err(AddressSpaceError::InvalidFrame);
            }
            let covering_range = base.as_usize()..(base.as_usize() + frame.size());

            // Check that no previous mapping covers the range we're trying to map
            for (vbase, (frame, rights)) in self.mappings.iter() {
                let total_range = core::cmp::max(*vbase + frame.size(), covering_range.end)
                    - core::cmp::min(*vbase, covering_range.start);
                let sum_ranges =
                    ((vbase + frame.size()) - *vbase) + (covering_range.end - covering_range.start);
                if sum_ranges > total_range {
                    return Err(AddressSpaceError::AlreadyMapped);
                }
            }

            self.mappings.insert(base.as_usize(), (frame, action));
            Ok(())
        }

        fn map_memory_requirements(base: VAddr, frames: &[Frame]) -> usize {
            // Implementation specific, the model does not require additional
            // page-table memory
            0
        }

        fn adjust(
            &mut self,
            base: VAddr,
            length: usize,
            new_rights: MapAction,
        ) -> Result<usize, AddressSpaceError> {
            let covering_range = base.as_usize()..(base.as_usize() + length);
            let mut adjusted = 0;
            for (_base, (frame, rights)) in self.mappings.range_mut(covering_range) {
                // Update the rights for all mappings in covering_range
                *rights = new_rights;
                adjusted += 1;
            }

            Ok(adjusted)
        }

        fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError> {
            for (base, (frame, rights)) in self.mappings.iter() {
                let covering_range = *base..(*base + frame.size());
                if covering_range.contains(&vaddr.as_usize()) {
                    let offset = vaddr.as_usize() - covering_range.start;
                    return Ok((frame.base + offset, *rights));
                }
            }

            Err(AddressSpaceError::NotMapped)
        }

        fn unmap(&mut self, base: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError> {
            let (frame, rights) = self
                .mappings
                .remove(&base.as_usize())
                .ok_or(AddressSpaceError::NotMapped)?;

            Ok((TlbFlushHandle {}, frame))
        }
    }

    /// A simple test to see if our model is doing what it's supposed to do.
    #[test]
    fn model_sanity_check() {
        let mut a: ModelAddressSpace = Default::default();
        let mut tcache = TCache::new(0, 0);

        let va = VAddr::from(0xffff_0000u64);
        let frame_base = PAddr::from(0xdeaf_0000u64);
        let frame = Frame::new(frame_base, 4096, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect("Can't map frame");

        let (ret_paddr, ret_rights) = a.resolve(va).expect("Can't resolve");
        assert_eq!(ret_paddr, frame_base);
        assert_eq!(ret_rights, MapAction::ReadKernel);

        let e = a
            .resolve(VAddr::from(0xffff_1000u64))
            .expect_err("resolve should not have succeeded");
        assert_eq!(e, AddressSpaceError::NotMapped);

        let ret = a
            .adjust(va, 4096, MapAction::ReadWriteUser)
            .expect("Can't adjust");
        assert_eq!(ret, 1);

        let ret = a
            .adjust(VAddr::from(0xffff_1000u64), 4096, MapAction::None)
            .expect("Can't adjust");
        assert_eq!(ret, 0);

        let (ret_paddr, ret_rights) = a.resolve(va).expect("Can't resolve");
        assert_eq!(ret_paddr, frame_base);
        assert_eq!(ret_rights, MapAction::ReadWriteUser);

        let (handle, ret_frame) = a.unmap(va).expect("Can't unmap");
        assert_eq!(ret_frame, frame);

        let e = a
            .unmap(va)
            .expect_err("unmap of not mapped region succeeds?");
        assert_eq!(e, AddressSpaceError::NotMapped);
    }

    #[test]
    fn model_bug_already_mapped() {
        let mut a: ModelAddressSpace = Default::default();
        let mut tcache = TCache::new(0, 0);

        let va = VAddr::from(0x489000);
        let frame_base = PAddr::from(0xdeaf_0000u64);
        let frame = Frame::new(frame_base, 4096, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect("Can't map frame");

        let va = VAddr::from(0xd4000);
        let frame_base = PAddr::from(0xde_0000);
        let frame = Frame::new(frame_base, 0x3b6000, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect_err("Could map frame");
    }

    #[test]
    fn model_bug_already_mapped2() {
        //let _r = env_logger::try_init();
        let mut a: ModelAddressSpace = Default::default();
        let mut tcache = TCache::new(0, 0);

        let va = VAddr::from(0x1ad000);
        let frame_base = PAddr::from(0x0);
        let frame = Frame::new(frame_base, 0xa7000, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect("Failed to map frame?");

        let va = VAddr::from(0x1ae000);
        let frame_base = PAddr::from(0x0);
        let frame = Frame::new(frame_base, 0x1000, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect_err("Could map frame?");
    }

    /// map_frame should allow increase of mapping
    #[test]
    fn from_ptflags() {
        let ru = PTFlags::P | PTFlags::US | PTFlags::XD;
        let ma: MapAction = ru.into();
        assert_eq!(ma, MapAction::ReadUser);

        let rk = PTFlags::XD | PTFlags::P;
        assert_ne!(ru, rk);
        let ma: MapAction = rk.into();
        assert_eq!(ma, MapAction::ReadKernel);
    }
}
