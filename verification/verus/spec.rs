use builtin::*;
use builtin_macros::*;
#[macro_use]
use crate::pervasive::*;
use seq::*;
use map::*;
use crate::{seq, seq_insert_rec, map, map_insert_rec};

pub struct MemRegion { pub base: nat, pub size: nat }

// TODO use VAddr, PAddr

#[spec]
pub struct PageTableContents {
    pub map: Map<nat /* VAddr */, MemRegion>,
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
    #[spec]
    pub fn inv(&self) -> bool {
        true
        && forall(|b1: nat, b2: nat| 
        // TODO: let vregion1, vregion2
            (self.map.dom().contains(b1) && self.map.dom().contains(b2)) >>= ((b1 == b2) || !overlap(
                MemRegion { base: b1, size: self.map.index(b1).size },
                MemRegion { base: b2, size: self.map.index(b2).size }
            )))
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

    // TODO later /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    // TODO later fn adjust(self, vaddr: nat) -> Result<(VAddr, usize), KError>;

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
    // let after = addrspace.map_frame(base, frame);
    // forall(|b1: nat, b2: nat| {
    //     requires(after.map.dom().contains(b1) && after.map.dom().contains(b2));
    //     ensures((b1 == b2) || !overlap(
    //         MemRegion { base: b1, size: after.map.index(b1).size },
    //         MemRegion { base: b2, size: after.map.index(b2).size }
    //     ));
    // });
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
        // assume(!overlap(
        //     MemRegion { base: b1, size: after.map.index(b1).size },
        //     MemRegion { base: b2, size: after.map.index(b2).size }
        // ));
        assume(false);
    });

    assert(forall(|b1: nat, b2:nat| after.map.dom().contains(b1) && after.map.dom().contains(b2)
        >>=
        !overlap(
            MemRegion { base: b1, size: after.map.index(b1).size },
            MemRegion { base: b2, size: after.map.index(b2).size }
        )));

    assert(addrspace.unmap(base).inv());


}

#[spec] #[is_variant]
pub enum NodeEntry {
    Directory(PrefixTreeNode),
    Page(MemRegion),
}

#[spec]
pub fn strictly_decreasing(s: Seq<nat>) -> bool {
    forall(|i: nat, j: nat| i < j && j < s.len() >>= s.index(i) > s.index(j))
}

// Root [8, 16, 24]

pub struct Arch {
    pub layer_sizes: Seq<nat>,
}

impl Arch {
    #[spec]
    pub fn inv(&self) -> bool {
        strictly_decreasing(self.layer_sizes)
    }
}

#[spec]
pub struct PrefixTreeNode {
    pub map: Map<nat /* addr */, Box<NodeEntry>>, // consider using the entry index
    pub layer: nat,       // 1 GiB, 2 MiB, 4 KiB
    pub base_vaddr: nat,
}

// page_size, next_sizes
// 2**40    , [ 2 ** 30, 2 ** 20 ]
// 2**30    , [ 2 ** 20 ]
// 2**20    , [ ]

fndecl!(pub fn pow2(v: nat) -> nat);


impl PrefixTreeNode {
    #[spec]
    pub fn entry_size(&self, arch: &Arch) -> nat {
        arch.layer_sizes.index(self.layer as int + 1)
    }

    #[spec]
    pub fn layer_size(&self, arch: &Arch) -> nat {
        arch.layer_sizes.index(self.layer as int)
    }

    #[spec]
    pub fn entries_are_entry_size_aligned(&self, arch: &Arch) -> bool {
        forall(|offset: nat| self.map.dom().contains(offset) >>= base_page_aligned(offset, self.entry_size(arch)))
    }

    #[spec]
    pub fn entries_fit_in_layer_size(&self, arch: &Arch) -> bool {
        forall(|offset: nat| self.map.dom().contains(offset) >>= offset < self.layer_size(arch))
    }

    #[spec]
    pub fn pages_match_entry_size(&self, arch: &Arch) -> bool {
        forall(|offset: nat| (self.map.dom().contains(offset) && self.map.index(offset).is_Page())
               >>= self.map.index(offset).get_Page_0().size == self.entry_size(arch))
    }

    #[spec]
    pub fn directories_are_in_next_layer(&self, arch: &Arch) -> bool {
        forall(|offset: nat| (self.map.dom().contains(offset) && self.map.index(offset).is_Directory())
               >>= {
                    let directory = self.map.index(offset).get_Directory_0();
                    true
                    && directory.layer == self.layer + 1
                    && directory.base_vaddr == self.base_vaddr + offset
                })
    }

    #[spec]
    pub fn directories_obey_invariant(&self, arch: &Arch) -> bool {
        decreases(arch.layer_sizes.len() - self.layer);

        forall(|offset: nat| (self.map.dom().contains(offset) && self.map.index(offset).is_Directory())
               >>= self.map.index(offset).get_Directory_0().inv(arch))
    }

    #[spec]
    pub fn inv(&self, arch: &Arch) -> bool {
        decreases(arch.layer_sizes.len() - self.layer);

        true
        && self.map.dom().finite()
        && self.layer < arch.layer_sizes.len()
        && self.entries_are_entry_size_aligned(arch)
        && self.entries_fit_in_layer_size(arch)
        && self.pages_match_entry_size(arch)
        && self.directories_are_in_next_layer(arch)
        && self.directories_obey_invariant(arch)
    }

    #[spec]
    pub fn interp(self, arch: &Arch) -> PageTableContents {
        arbitrary()
    }

    #[spec]
    pub fn map_frame(self, arch: &Arch, vaddr: nat, frame: MemRegion) -> PrefixTreeNode {
        decreases(arch.layer_sizes.len() - self.layer);

        let offset = vaddr - self.base_vaddr;
        if frame.size == self.entry_size(arch) {
            PrefixTreeNode {
                map: self.map.insert(offset, box NodeEntry::Page(frame)),
                ..self
            }
        } else {
            let binding_offset = offset - (offset % self.entry_size(arch)); // 0xf374 -- entry_size 0x100 --> 0xf300
            let directory: PrefixTreeNode = if self.map.dom().contains(offset) {
                self.map.index(binding_offset).get_Directory_0()
            } else {
                PrefixTreeNode {
                    map: map![],
                    layer: self.layer + 1,
                    base_vaddr: self.base_vaddr 
                }
            };
            let updated_directory = directory.map_frame(arch, vaddr, frame);
            PrefixTreeNode {
                map: self.map.insert(binding_offset, box NodeEntry::Directory(updated_directory)),
                ..self
            }
        }
    }

    // NOTE: maybe return whether the frame was unmapped
    // #[spec] pub fn unmap_frame(self, base: nat) -> (nat /* size */, PrefixTreeNode) {
    //     decreases(self.next_sizes.len());

    //     if base % self.page_size == 0 {
    //         if self.map.dom().contains(base) {
    //             (
    //                 self.page_size,
    //                 PrefixTreeNode {
    //                     map: self.map.remove(base),
    //                     ..self
    //                 }
    //             )
    //         } else {
    //             arbitrary()
    //         }
    //     } else {
    //         let directory_addr = base % self.page_size;
    //         if self.map.dom().contains(directory_addr) {
    //             let (page_size, directory) = self.map.index(directory_addr).get_Directory_0().unmap_frame(base);
    //             (
    //                 page_size,
    //                 if directory.map.dom().len() > 0 {
    //                     PrefixTreeNode {
    //                         map: self.map.insert(directory_addr, box NodeEntry::Directory(directory)),
    //                         ..self
    //                     }
    //                 } else {
    //                     PrefixTreeNode {
    //                         map: self.map.remove(directory_addr),
    //                         ..self
    //                     }
    //                 }
    //             )
    //         } else {
    //             arbitrary()
    //         }
    //     }
    // }
}

// #[proof]
// fn next_sizes_len_decreases(node: PrefixTreeNode) {
//     requires(node.inv());
//     ensures(forall(|i: nat| i < node.next_sizes.len() >>= node.page_size > node.next_sizes.index(i)));
// 
//     if node.next_sizes.len() == 0 {
//     } else {
//         forall(|i: nat| {
//             requires(i < node.next_sizes.len());
//             ensures(node.page_size > node.next_sizes.index(i));
// 
//             if i == 0 {
//             } else {
//             }
//         });
//     }
// }
// 
// #[proof]
// fn map_frame_preserves_inv_2(node: PrefixTreeNode, base: nat, frame: MemRegion) {
//     requires(node.inv() && node.view().accepted_mapping(base, frame) && frame.size <= node.page_size);
//     ensures(node.map_frame(base, frame).inv());
// }


// #[proof]
// fn map_frame_contradiction(node: PrefixTreeNode, base: nat, frame: MemRegion) {
//     #[spec] let new_node = node.map_frame(base, frame);
//     assert(false);
// }

// #[exec] fn unmap_frame(&mut self, vaddr: usize) {
//     requires(self.view().map.dom().contains(vaddr));
//     ensures(self.view().map == old(self).view().map.remove(vaddr));
// }

// #[exec] fn unmap_frame(&mut self, vaddr: usize) -> (Option<()>, Frame) {
//     ensures(|res: Option<()>| [
//         if self.view().map.dom().contains(vaddr) {
//             true
//             && res == Some(())
//             && self.view().map == old(self).view().map.remove(vaddr)
//         } else {
//             true
//             && res == None
//             && equal(self, old(self))
//         }
//     ])
// }

// #[exec] fn actually_resolve(self, vaddr: usize) -> ActualMemRegion {
//     requires(self.view().map.dom().contains(vaddr));
// }
//

// NOTE: pages are 1 GiB, 2 MiB, 4 KiB
// NOTE: on ARM consecutive entries in vspace and physical space, one TLB entry
// NOTE: the memory alloc may fail
// NOTE: use linearity to prevent a frame being mapped in the kernel and user-space at the same
// time
