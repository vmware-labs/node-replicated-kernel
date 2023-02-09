// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{Eq, PartialEq};

use proptest::prelude::*;
use x86::current::paging::PTFlags;

use crate::error::KError;
use crate::memory::vspace_model::ModelAddressSpace;
use crate::memory::KernelAllocator;
use crate::memory::{MemType, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use crate::*;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestAction {
    Map(VAddr, Frame, MapAction),
    Adjust(VAddr, MapAction),
    Resolve(VAddr),
    Unmap(VAddr),
}

fn action() -> impl Strategy<Value = TestAction> {
    // Generate a possible action for applying on the vspace,
    // note we currently assume that a frame is either of base-page
    // or large-page size. Arbitrary frames are possible to map
    // but our (simple) vspace can only unmap one page-table
    // entry at a time.
    prop_oneof![
        (
            vaddrs(0x60_0000),
            frames(0x60_0000, 0x40_0000),
            map_rights()
        )
            .prop_map(|(a, b, c)| TestAction::Map(a, b, c)),
        (vaddrs(0x60_0000), map_rights()).prop_map(|(a, b)| TestAction::Adjust(a, b)),
        vaddrs(0x60_0000).prop_map(TestAction::Unmap),
        vaddrs(0x60_0000).prop_map(TestAction::Resolve),
    ]
}

fn actions() -> impl Strategy<Value = Vec<TestAction>> {
    prop::collection::vec(action(), 0..512)
}

fn map_rights() -> impl Strategy<Value = MapAction> {
    prop_oneof![
        Just(MapAction::user()),
        Just(MapAction::kernel()),
        Just(MapAction::write()),
        Just(MapAction::kernel() | MapAction::write()),
        Just(MapAction::execute()),
        Just(MapAction::kernel() | MapAction::execute()),
        Just(MapAction::write() | MapAction::execute()),
        Just(MapAction::kernel() | MapAction::write() | MapAction::execute()),
    ]
}

fn page_sizes() -> impl Strategy<Value = usize> {
    prop::sample::select(vec![BASE_PAGE_SIZE, LARGE_PAGE_SIZE])
}

prop_compose! {
    fn frames(max_base: u64, _max_size: usize)(base in base_aligned_addr(max_base), size in page_sizes()) -> Frame {
        let paddr = if base & 0x1 > 0 {
            PAddr::from(base).align_down_to_base_page()
        } else {
            PAddr::from(base).align_down_to_large_page()
        };

        Frame::new(paddr, size, 0)
    }
}

prop_compose! {
    fn vaddrs(max: u64)(base in 0..max) -> VAddr { VAddr::from(base & !0xfff) }
}

prop_compose! {
    fn base_aligned_addr(max: u64)(base in 0..max) -> u64 { base & !0xfff }
}

prop_compose! {
    fn large_aligned_addr(max: u64)(base in 0..max) -> u64 { base & !0x1fffff }
}

proptest! {
    // Verify that our implementation behaves according to the `ModelAddressSpace`.
    #[test]
    fn model_equivalence(ops in actions()) {
        use TestAction::*;
        use crate::memory::detmem::DA;

        let mut totest = VSpace::new(Box::new(DA::new().expect("Unable to create DA"))).expect("Unable to create vspace");;
        let mut model: ModelAddressSpace = Default::default();

        for action in ops {
            match action {
                Map(base, frame, rights) => {
                    KernelAllocator::try_refill_tcache(14, 14, MemType::Mem).expect("Can't refill FrameCacheSmall");
                    let rmodel = model.map_frame(base, frame, rights);
                    let rtotest = totest.map_frame(base, frame, rights);
                    match (&rtotest, &rmodel) {
                        // For now we let the model and impl report different conflict addresses
                        // ideally they should still be valid conflicts (not checked) just different ones
                        (Err(KError::AlreadyMapped { base: _a }), Err(KError::AlreadyMapped { base: _b })) => {},
                        _ => assert_eq!(rmodel, rtotest),
                    }
                }
                Adjust(vaddr, rights) => {
                    let rmodel = model.adjust(vaddr, rights);
                    let rtotest = totest.adjust(vaddr, rights);
                    assert_eq!(rmodel, rtotest);
                }
                Resolve(vaddr) => {
                    let rmodel = model.resolve(vaddr);
                    let rtotest = totest.resolve(vaddr);
                    assert_eq!(rmodel, rtotest);
                }
                Unmap(vaddr) => {
                    let rmodel = model.unmap(vaddr);
                    let rtotest = totest.unmap(vaddr);
                    assert_eq!(rmodel, rtotest);
                }
            }
        }
    }
}

/// map_frame should allow increase of mapping
#[test]
fn from_ptflags() {
    let ru = PTFlags::P | PTFlags::US | PTFlags::XD;
    let ma: MapAction = ru.into();
    assert_eq!(ma, MapAction::user());

    let rk = PTFlags::XD | PTFlags::P;
    assert_ne!(ru, rk);
    let ma: MapAction = rk.into();
    assert_eq!(ma, MapAction::kernel());
}
