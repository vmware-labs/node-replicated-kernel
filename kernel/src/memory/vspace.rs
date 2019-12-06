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
        // s
        frames: &Vec<(Frame, MapAction)>,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        let mut cur_base = base;
        for (frame, action) in frames.into_iter() {
            self.map_frame(cur_base, *frame, *action, pager)?;
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

    /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    ///
    /// # Returns
    /// The range (vregion) that was adjusted if successfull.
    fn adjust(
        &mut self,
        vaddr: VAddr,
        rights: MapAction,
    ) -> Result<(VAddr, usize), AddressSpaceError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError>;

    /// Removes the frame from the address space that contains `vaddr`.
    ///
    /// # Returns
    /// The frame to the caller along with a `TlbFlushHandle` that may have to be
    /// invoked to flush the TLB.
    fn unmap(&mut self, vaddr: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError>;

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
    InvalidBase = "The supplied base was invalid (alignment?)",
}

impl Into<SystemCallError> for AddressSpaceError {
    fn into(self) -> SystemCallError {
        match self {
            AddressSpaceError::InvalidFrame => SystemCallError::InternalError,
            AddressSpaceError::AlreadyMapped => SystemCallError::InternalError,
            AddressSpaceError::BaseOverflow { .. } => SystemCallError::InternalError,
            AddressSpaceError::NotMapped => SystemCallError::InternalError,
            AddressSpaceError::InvalidLength => SystemCallError::InternalError,
            AddressSpaceError::InvalidBase => SystemCallError::InternalError,
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

/// Implementation of a model vspace (for testing)
#[cfg(test)]
pub(crate) mod model {
    use super::*;
    use crate::memory::tcache::TCache;
    use crate::memory::{BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
    use alloc::collections::BTreeMap;
    use core::iter::Iterator;
    use core::ops::Range;

    /// A simple model address space
    ///
    /// Can be used by property testing to see if a hardware address space
    /// implementation is equivalent.
    pub(crate) struct ModelAddressSpace {
        // Stores all mappings [VAddr, VAddr+length] -> [PAddr, PAddr+length]
        oplog: Vec<(VAddr, PAddr, usize, MapAction)>,
    }

    impl ModelAddressSpace {
        /// Checks if there is overlap between two ranges
        fn overlaps<T: PartialOrd>(a: &core::ops::Range<T>, b: &core::ops::Range<T>) -> bool {
            a.start < b.end && b.start < a.end
        }

        /// A very silly O(n) method that caculates the intersection between two ranges
        fn intersection(
            a: core::ops::Range<usize>,
            b: core::ops::Range<usize>,
        ) -> Option<core::ops::Range<usize>> {
            if ModelAddressSpace::overlaps(&a, &b) {
                let mut min = usize::max_value();
                let mut max = 0;

                for element in a {
                    if b.contains(&element) {
                        min = core::cmp::min(element, min);
                        max = core::cmp::max(element, max);
                    }
                }
                Some(min..max + 1)
            } else {
                None
            }
        }
    }

    impl Default for ModelAddressSpace {
        fn default() -> ModelAddressSpace {
            ModelAddressSpace {
                oplog: Vec::with_capacity(512),
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
            // Don't allow mapping of zero-sized frames
            if frame.size() == 0 {
                return Err(AddressSpaceError::InvalidFrame);
            }
            if frame.base % frame.size() != 0 {
                // phys addr should be aligned to page-size
                return Err(AddressSpaceError::InvalidFrame);
            }
            if base % frame.size() != 0 {
                // virtual addr should be aligned to page-size
                return Err(AddressSpaceError::InvalidBase);
            }

            // Is there an existing mapping that conflicts with the new mapping?
            for (cur_vaddr, cur_paddr, length, rights) in self.oplog.iter_mut().rev() {
                let cur_range = cur_vaddr.as_usize()..cur_vaddr.as_usize() + *length;
                let new_range = base.as_usize()..base.as_usize() + frame.size();
                if ModelAddressSpace::overlaps(&cur_range, &new_range) {
                    if cur_range.start == new_range.start
                        && cur_range.end <= new_range.end
                        && *cur_paddr == frame.base
                        && *rights == action
                    {
                        // Promote frame size in the special case where we can just extend
                        // an existing mapping
                        *length = frame.size();
                        return Ok(());
                    } else {
                        return Err(AddressSpaceError::AlreadyMapped);
                    }
                }
            }

            // No? Then add the new mapping
            self.oplog.push((base, frame.base, frame.size(), action));
            Ok(())
        }

        fn map_memory_requirements(base: VAddr, frames: &[Frame]) -> usize {
            // Implementation specific, the model does not require additional
            // memory for page-tables
            0
        }

        fn adjust(
            &mut self,
            base: VAddr,
            new_rights: MapAction,
        ) -> Result<(VAddr, usize), AddressSpaceError> {
            if !base.is_base_page_aligned() {
                return Err(AddressSpaceError::InvalidBase);
            }

            for (cur_vaddr, cur_paddr, cur_length, cur_rights) in self.oplog.iter_mut().rev() {
                if base >= *cur_vaddr && base < (*cur_vaddr + *cur_length) {
                    *cur_rights = new_rights;
                    return Ok((*cur_vaddr, *cur_length));
                }
            }

            Err(AddressSpaceError::NotMapped)
        }

        fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError> {
            // Walk through mappings, find mapping containing vaddr, return
            for (cur_vaddr, cur_paddr, length, rights) in self.oplog.iter().rev() {
                let cur_range = cur_vaddr.as_usize()..cur_vaddr.as_usize() + *length;
                if cur_range.contains(&vaddr.as_usize()) {
                    let offset = vaddr - *cur_vaddr;
                    let paddr = *cur_paddr + offset.as_usize();
                    return Ok((paddr, *rights));
                }
            }

            // The `vaddr` in question is not currently mapped
            Err(AddressSpaceError::NotMapped)
        }

        fn unmap(&mut self, base: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError> {
            if !base.is_base_page_aligned() {
                return Err(AddressSpaceError::InvalidBase);
            }

            let mut found =
                self.oplog
                    .drain_filter(|(cur_vaddr, cur_paddr, cur_length, cur_rights)| {
                        base >= *cur_vaddr && base < (*cur_vaddr + *cur_length)
                    });

            let element = found.next();
            if element.is_some() {
                let (cur_vaddr, cur_paddr, cur_length, cur_rights) = element.unwrap();
                assert!(found.next().is_none(), "Only found one relevant mapping");
                Ok((TlbFlushHandle {}, Frame::new(cur_paddr, cur_length, 0)))
            } else {
                Err(AddressSpaceError::NotMapped)
            }
        }
    }

    /// A simple test to see if our model is doing what it's supposed to do.
    #[test]
    fn model_sanity_check() {
        let mut a: ModelAddressSpace = Default::default();
        let mut tcache = TCache::new(0, 0);

        let va = VAddr::from(0xffff_0000u64);
        let frame_base = PAddr::from(0xdeaf_0000u64);
        let frame = Frame::new(frame_base, BASE_PAGE_SIZE, 0);

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

        a.adjust(va, MapAction::ReadWriteUser)
            .expect("Can't adjust");

        a.adjust(VAddr::from(0xffff_1000u64), MapAction::None)
            .expect_err("Adjusted unmapped region?");

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
        let frame = Frame::new(frame_base, 0x1000, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadKernel, &mut tcache)
            .expect("Failed to map frame?");

        let va = VAddr::from(0x1ad000);
        let frame_base = PAddr::from(0x0);
        let frame = Frame::new(frame_base, 0x1000, 0);

        let ret = a
            .map_frame(va, frame, MapAction::ReadExecuteUser, &mut tcache)
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

    #[test]
    fn half_range_overlaps() {
        let r1 = 1..3;
        let r2 = 2..5;
        assert!(ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 5..15;
        let r2 = 0..5;
        assert!(!ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 10..15;
        let r2 = 0..10;
        assert!(!ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 0..10;
        let r2 = 10..15;
        assert!(!ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 0..10;
        let r2 = 9..10;
        assert!(ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 0..10;
        let r2 = 9..11;
        assert!(ModelAddressSpace::overlaps(&r1, &r2));

        let r1 = 0..10;
        let r2 = 11..12;
        assert!(!ModelAddressSpace::overlaps(&r1, &r2));
    }

    #[test]
    fn half_range_intersections() {
        let r1 = 1..3;
        let r2 = 2..5;
        assert_eq!(ModelAddressSpace::intersection(r1, r2).unwrap(), 2..3);

        let r1 = 5..15;
        let r2 = 0..9;
        assert_eq!(ModelAddressSpace::intersection(r1, r2).unwrap(), 5..9);

        let r1 = 10..15;
        let r2 = 0..10;
        assert!(ModelAddressSpace::intersection(r1, r2).is_none());

        let r1 = 0..10;
        let r2 = 10..15;
        assert!(ModelAddressSpace::intersection(r1, r2).is_none());

        let r1 = 0..10;
        let r2 = 9..10;
        assert_eq!(ModelAddressSpace::intersection(r1, r2).unwrap(), 9..10);

        let r1 = 0..10;
        let r2 = 9..11;
        assert_eq!(ModelAddressSpace::intersection(r1, r2).unwrap(), 9..10);

        let r1 = 0..10;
        let r2 = 11..12;
        assert!(ModelAddressSpace::intersection(r1, r2).is_none());
    }
}
