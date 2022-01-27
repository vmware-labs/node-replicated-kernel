use builtin::*;

use crate::memory_types::*;

use crate::pervasive::{*, result::Result, result::Result::*};
use map::*;

#[spec]
pub struct AddressSpace {
    pub map: Map<nat, MemRegion>,
}

#[spec]
pub fn base_page_aligned(addr: nat) -> bool {
    addr % BASE_PAGE_SIZE == 0
}

#[spec]
pub fn overlap(region1: MemRegion, region2: MemRegion) -> bool {
    if region1.base <= region2.base {
        region1.base + region1.size <= region2.base
    } else {
        region2.base + region2.size <= region1.base
    }
}

impl AddressSpace {
    #[spec]
    pub fn inv(&self) -> bool { true
        && forall(|b1: nat, b2: nat| 
            (self.map.dom().contains(b1) && self.map.dom().contains(b2)) >>= !overlap(
                MemRegion { base: b1, size: self.map.index(b1).size },
                MemRegion { base: b2, size: self.map.index(b2).size }
            ))
        && forall(|b1: nat, b2: nat|
            (self.map.dom().contains(b1) && self.map.dom().contains(b2)) >>= !overlap(
                self.map.index(b1),
                self.map.index(b2)
            ))
    }

    #[spec] pub fn accepted_mapping(&self, base: nat, frame: MemRegion) -> bool {
        true
        && base_page_aligned(base)
        && base_page_aligned(frame.base)
        && forall(|b: nat| self.map.dom().contains(b) >>= !overlap(
                MemRegion { base: base, size: frame.size },
                MemRegion { base: b, size: self.map.index(b).size }
           ))
        && forall(|b: nat| self.map.dom().contains(b) >>= !overlap(
                frame,
                self.map.index(b)
           ))
    }

    /// Maps the given `frame` at `base` in the address space
    #[spec] pub fn map_frame(self, base: nat, frame: MemRegion) -> AddressSpace {
        if self.accepted_mapping(base, frame) {
            AddressSpace {
                map: self.map.insert(base, frame),
                ..self
            }
        } else {
            arbitrary()
        }
    }

    // /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    // fn adjust(self, vaddr: nat) -> Result<(VAddr, usize), KError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    #[spec] fn resolve(self, vaddr: nat) -> Result<nat, ()> {
        arbitrary()
    }

    /// Removes the frame from the address space that contains `vaddr`.
    #[spec] fn unmap(self, vaddr: nat) -> Result<AddressSpace, ()> {
        Ok(self)
    }
}

#[proof] fn map_frame_preserves_inv(addrspace: AddressSpace, base: nat, frame: MemRegion) {
    requires([
        addrspace.inv(),
        addrspace.accepted_mapping(base, frame),
    ]);
    ensures([
        addrspace.inv()
    ]);
}
