use builtin::*;
use builtin_macros::*;
#[macro_use]
use crate::pervasive::*;
use seq::*;
use map::*;
use crate::{seq, seq_insert_rec, map, map_insert_rec};

pub struct MemRegion { pub base: nat, pub size: nat }

#[spec]
pub struct PageTableContents {
    pub map: Map<nat, MemRegion>,
}

#[spec]
pub fn base_page_aligned(addr: nat, size: nat) -> bool {
    addr % size == 0
}

#[spec]
pub fn overlap(region1: MemRegion, region2: MemRegion) -> bool {
    if region1.base <= region2.base {
        region1.base + region1.size <= region2.base
    } else {
        region2.base + region2.size <= region1.base
    }
}

impl PageTableContents {
    #[spec] #[verifier(pub_abstract)]
    pub fn inv(&self) -> bool {
        true
        && forall(|b1: nat, b2: nat| 
            (self.map.dom().contains(b1) && self.map.dom().contains(b2)) >>= !overlap(
                MemRegion { base: b1, size: self.map.index(b1).size },
                MemRegion { base: b2, size: self.map.index(b2).size }
            ))
    }

    #[spec] pub fn accepted_mapping(self, base: nat, frame: MemRegion) -> bool {
        true
        && base_page_aligned(base, frame.size)
        && base_page_aligned(frame.base, frame.size)
        && forall(|b: nat| self.map.dom().contains(b) >>= !overlap(
                MemRegion { base: base, size: frame.size },
                MemRegion { base: b, size: self.map.index(b).size }
           ))
    }

    /// Maps the given `frame` at `base` in the address space
    #[spec] pub fn map_frame(self, base: nat, frame: MemRegion) -> PageTableContents {
        if self.accepted_mapping(base, frame) {
            PageTableContents {
                map: self.map.insert(base, frame),
                ..self
            }
        } else {
            arbitrary()
        }
    }

    // predicate (function -> bool)
    // #[spec] pub fn step_map_frame(&self /* s */, post: &PageTableContents /* s' */, base:nat, frame: MemRegion) -> bool {
    //     post == self.map_frame(base, frame)
    // }

    // /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    // fn adjust(self, vaddr: nat) -> Result<(VAddr, usize), KError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    #[spec] fn resolve(self, vaddr: nat) -> MemRegion {
        self.map.index(vaddr)
    }

    /// Removes the frame from the address space that contains `base`.
    #[spec] fn unmap(self, base: nat) -> PageTableContents {
        if self.map.dom().contains(base) {
            PageTableContents {
                map: self.map.remove(base),
                ..self
            }
        } else {
            arbitrary()
        }
    }
}

// lemma MapFramePreserveInv(addrspace: PageTableContents, base: nat, frame: MemRegion)
#[proof] fn map_frame_preserves_inv(addrspace: PageTableContents, base: nat, frame: MemRegion) {
    requires([
        addrspace.inv(),
        addrspace.accepted_mapping(base, frame),
    ]);
    ensures([
        addrspace.map_frame(base, frame).inv()
    ]);
    let after = addrspace.map_frame(base, frame);
    forall(|b1: nat, b2: nat| {
        requires(after.map.dom().contains(b1) && after.map.dom().contains(b2));
        ensures(!overlap(
            MemRegion { base: b1, size: after.map.index(b1).size },
            MemRegion { base: b2, size: after.map.index(b2).size }
        ));
        assume(!overlap(
            MemRegion { base: b1, size: after.map.index(b1).size },
            MemRegion { base: b2, size: after.map.index(b2).size }
        ));
    });
}

#[proof] fn unmap_frame_preserves_inv(addrspace: PageTableContents, base: nat) {
    requires([
        addrspace.inv(),
    ]);
    ensures([
        addrspace.unmap(base).inv()
    ]);
    let after = addrspace.unmap(base);
    forall(|b1: nat, b2: nat| {
        requires(after.map.dom().contains(b1) && after.map.dom().contains(b2));
        ensures(!overlap(
            MemRegion { base: b1, size: after.map.index(b1).size },
            MemRegion { base: b2, size: after.map.index(b2).size }
        ));
        assume(!overlap(
            MemRegion { base: b1, size: after.map.index(b1).size },
            MemRegion { base: b2, size: after.map.index(b2).size }
        ));
    });
}

#[spec] #[is_variant]
pub enum NodeEntry {
    Directory(PrefixTreeNode),
    Page(MemRegion),
}

#[spec]
pub struct PrefixTreeNode {
    pub map: Map<nat /* prefix */, Box<NodeEntry>>,
    pub prefix_size: nat,
    pub next_sizes: Seq<nat>,
}

fndecl!(pub fn pow2(v: nat) -> nat);

impl PrefixTreeNode {
    #[spec] #[verifier(pub_abstract)]
    pub fn inv(&self) -> bool {
        decreases(self.next_sizes.len());

        true
        && self.map.dom().finite()
        // && exists(|i: nat| self.prefix_size == 1 << i)
        && forall(|b: nat| self.map.dom().contains(b) >>= b % self.prefix_size == 0)
        && if self.next_sizes.len() == 0 {
            forall(|b: nat| self.map.dom().contains(b) >>= self.map.index(b).is_Page())
        } else {
            self.prefix_size < self.next_sizes.index(0)
        }
        && forall(|b: nat| (self.map.dom().contains(b) && self.map.index(b).is_Directory()) >>= {
            let directory = self.map.index(b).get_Directory_0();
            true
            && equal(directory.next_sizes, self.next_sizes.subrange(1, self.next_sizes.len()))
            && directory.prefix_size == self.next_sizes.index(0)
            && self.map.index(b).get_Directory_0().inv()
        })
    }

    #[spec]
    pub fn view(&self) -> PageTableContents {
        arbitrary()
    }

    // NOTE: pages are 1 GiB, 2 MiB, 4 KiB
    // NOTE: on ARM consecutive entries in vspace and physical space, one TLB entry
    // NOTE: the memory alloc may fail
    #[spec] pub fn map_frame(self, base: nat, frame: MemRegion) -> PrefixTreeNode {
        decreases(self.next_sizes.len());

        if self.inv() && self.view().accepted_mapping(base, frame) && frame.size <= self.prefix_size {
            if frame.size == self.prefix_size {
                PrefixTreeNode {
                    map: self.map.insert(base, box NodeEntry::Page(frame)),
                    ..self
                }
            } else {
                let directory = if self.map.dom().contains(base) {
                    self.map.index(base).get_Directory_0()
                } else {
                    PrefixTreeNode {
                        map: map![],
                        prefix_size: self.next_sizes.index(0),
                        next_sizes: self.next_sizes.subrange(1, self.next_sizes.len()),
                    }
                };
                let updated_directory = directory.map_frame(base, frame);
                PrefixTreeNode {
                    map: self.map.insert(base, box NodeEntry::Directory(updated_directory)),
                    ..self
                }
            }
        } else {
            arbitrary()
        }
    }
}

// #[exec] fn actually_resolve(self, vaddr: usize) -> ActualMemRegion {
//     requires(self.view().map.dom().contains(vaddr));
// }
//

