//! Implementation of a model vspace (for testing/model checking)
use core::iter::Iterator;

use super::vspace::*;
use crate::error::KError;
use crate::memory::{Frame, PAddr, VAddr, BASE_PAGE_SIZE};

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
            let mut min = usize::MAX;
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
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        // Don't allow mapping of zero-sized frames
        if frame.size() == 0 {
            return Err(KError::InvalidFrame);
        }
        if frame.base % frame.size() != 0 {
            // phys addr should be aligned to page-size
            return Err(KError::InvalidFrame);
        }
        if base % frame.size() != 0 {
            // virtual addr should be aligned to page-size
            return Err(KError::InvalidBase);
        }

        // Is there an existing mapping that conflicts with the new mapping?
        let mut overlapping_mappings = Vec::with_capacity(1);
        for (cur_vaddr, cur_paddr, length, rights) in self.oplog.iter_mut() {
            let cur_range = cur_vaddr.as_usize()..cur_vaddr.as_usize() + *length;
            let new_range = base.as_usize()..base.as_usize() + frame.size();
            if ModelAddressSpace::overlaps(&cur_range, &new_range) {
                if cur_range.start == new_range.start
                    && cur_range.end <= new_range.end
                    && *cur_paddr == frame.base
                    && *rights == action
                {
                    // Not really a conflict yet since we might be able to get away with
                    // just adjusting the mapping. We have to make sure we really
                    // don't have any conflicts with mappings that come later in the list
                    // (see also further down)
                } else {
                    overlapping_mappings.push(
                        ModelAddressSpace::intersection(cur_range, new_range)
                            .unwrap()
                            .start
                            .into(),
                    );
                }
            }
        }

        // No conflicts
        if overlapping_mappings.is_empty() {
            for (cur_vaddr, cur_paddr, length, rights) in self.oplog.iter_mut() {
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
                    }
                }
            }
        } else {
            // In case we have a mapping that conflicts return the first (lowest)
            // VAddr where a conflict happened:
            overlapping_mappings.sort_unstable();
            return Err(KError::AlreadyMapped {
                base: *overlapping_mappings.get(0).unwrap(),
            });
        }

        // No conflicts? Then add the new mapping
        self.oplog.push((base, frame.base, frame.size(), action));
        Ok(())
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        // Implementation specific, the model does not require additional
        // memory for page-tables
        0
    }

    fn adjust(&mut self, base: VAddr, new_rights: MapAction) -> Result<(VAddr, usize), KError> {
        if !base.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }

        for (cur_vaddr, _cur_paddr, cur_length, cur_rights) in self.oplog.iter_mut().rev() {
            if base >= *cur_vaddr && base < (*cur_vaddr + *cur_length) {
                *cur_rights = new_rights;
                return Ok((*cur_vaddr, *cur_length));
            }
        }

        Err(KError::NotMapped)
    }

    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), KError> {
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
        Err(KError::NotMapped)
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        if !base.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }

        let mut found =
            self.oplog
                .drain_filter(|(cur_vaddr, _cur_paddr, cur_length, _cur_rights)| {
                    base >= *cur_vaddr && base < (*cur_vaddr + *cur_length)
                });

        let element = found.next();
        if element.is_some() {
            let (cur_vaddr, cur_paddr, cur_length, cur_rights) = element.unwrap();
            assert!(found.next().is_none(), "Only found one relevant mapping");
            Ok(TlbFlushHandle::new(
                cur_vaddr, cur_paddr, cur_length, cur_rights,
            ))
        } else {
            Err(KError::NotMapped)
        }
    }
}

/// A simple test to see if our model is doing what it's supposed to do.
#[test]
fn model_sanity_check() {
    let mut a: ModelAddressSpace = Default::default();

    let va = VAddr::from(0xffff_0000u64);
    let frame_base = PAddr::from(0xdeaf_0000u64);
    let frame = Frame::new(frame_base, BASE_PAGE_SIZE, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::kernel())
        .expect("Can't map frame");

    let (ret_paddr, ret_rights) = a.resolve(va).expect("Can't resolve");
    assert_eq!(ret_paddr, frame_base);
    assert_eq!(ret_rights, MapAction::kernel());

    let e = a
        .resolve(VAddr::from(0xffff_1000u64))
        .expect_err("resolve should not have succeeded");
    assert_eq!(e, KError::NotMapped);

    a.adjust(va, MapAction::write()).expect("Can't adjust");

    a.adjust(VAddr::from(0xffff_1000u64), MapAction::none())
        .expect_err("Adjusted unmapped region?");

    let (ret_paddr, ret_rights) = a.resolve(va).expect("Can't resolve");
    assert_eq!(ret_paddr, frame_base);
    assert_eq!(ret_rights, MapAction::write());

    let handle = a.unmap(va).expect("Can't unmap");
    assert_eq!(handle.paddr, frame.base);
    assert_eq!(handle.size, frame.size);
    //TODO: assert_eq!(which_affinity(handle.paddr), frame.affinity);

    let e = a
        .unmap(va)
        .expect_err("unmap of not mapped region succeeds?");
    assert_eq!(e, KError::NotMapped);
}

#[test]
fn model_bug_already_mapped() {
    let mut a: ModelAddressSpace = Default::default();

    let va = VAddr::from(0x489000);
    let frame_base = PAddr::from(0xdeaf_0000u64);
    let frame = Frame::new(frame_base, 4096, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::kernel())
        .expect("Can't map frame");

    let va = VAddr::from(0xd4000);
    let frame_base = PAddr::from(0xde_0000);
    let frame = Frame::new(frame_base, 0x3b6000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::kernel())
        .expect_err("Could map frame");
}

#[test]
fn model_bug_already_mapped2() {
    //let _r = env_logger::try_init();
    let mut a: ModelAddressSpace = Default::default();

    let va = VAddr::from(0x1ad000);
    let frame_base = PAddr::from(0x0);
    let frame = Frame::new(frame_base, 0x1000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::kernel())
        .expect("Failed to map frame?");

    let va = VAddr::from(0x1ad000);
    let frame_base = PAddr::from(0x0);
    let frame = Frame::new(frame_base, 0x1000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::execute())
        .expect_err("Could map frame?");
}

#[test]
fn model_bug_already_mapped3() {
    let _r = env_logger::try_init();
    let mut a: ModelAddressSpace = Default::default();

    let va = VAddr::from(0x0);
    let frame = Frame::new(PAddr::from(0x0), 0x1000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::user())
        .expect("Failed to map frame?");

    let va = VAddr::from(0x1000);
    let frame = Frame::new(PAddr::from(0x0), 0x1000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::user())
        .expect("Failed to map frame?");

    let va = VAddr::from(0x0);
    let frame = Frame::new(PAddr::from(0x0), 0x20_0000, 0);

    let _ret = a
        .map_frame(va, frame, MapAction::user())
        .expect_err("Could map frame?");
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

#[test]
fn tlb_flush_handle_full_core_set() {
    use crate::arch::MAX_CORES;

    let mut t = TlbFlushHandle::new(VAddr::zero(), PAddr::zero(), 4096, MapAction::none());
    for i in 0..MAX_CORES {
        t.add_core(i);
    }

    let mut v = Vec::with_capacity(MAX_CORES);
    for c in t.cores() {
        v.push(c);
    }
    assert!(v.iter().cloned().eq(0..v.len()));
}

#[test]
fn tlb_flush_handle_empty_core_set() {
    let t = TlbFlushHandle::new(VAddr::zero(), PAddr::zero(), 4096, MapAction::none());
    assert_eq!(t.cores().count(), 0, "Is empty");
}

#[test]
fn tlb_flush_handle_med_core_set() {
    use crate::arch::MAX_CORES;

    let mut t = TlbFlushHandle::new(VAddr::zero(), PAddr::zero(), 4096, MapAction::none());
    for i in 0..MAX_CORES {
        t.add_core(i & !0b1);
    }

    for c in t.cores() {
        assert_eq!(c % 2, 0, "Is even");
    }
    assert_eq!(t.cores().count(), MAX_CORES / 2, "Correct length");
}

#[test]
#[should_panic]
fn tlb_flush_handle_invalid_core() {
    use crate::arch::MAX_CORES;
    let mut t = TlbFlushHandle::new(VAddr::zero(), PAddr::zero(), 4096, MapAction::none());

    let mtid = core::cmp::max(MAX_CORES + 1, (u128::BITS * 2) as usize);
    t.add_core(mtid);
}
