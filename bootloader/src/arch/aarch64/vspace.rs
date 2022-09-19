// Copyright © 2022 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::mem::transmute;

use armv8::aarch64::vm::granule4k::*;

use crate::kernel::*;
use crate::memory;

use crate::arch;

use crate::MapAction;

impl MapAction {
    fn set_l3_entry_rights(&self, entry: &mut L3Descriptor) {
        entry.read_only().user_exec_never().priv_exec_never();

        match self {
            MapAction::None => {
                entry.no_access();
            }
            MapAction::ReadUser | MapAction::ReadKernel => (),
            MapAction::ReadWriteUser | MapAction::ReadWriteKernel => {
                entry.read_write();
            }
            MapAction::ReadExecuteKernel => {
                entry.priv_exec();
            }
            MapAction::ReadExecuteUser => {
                entry.user_exec();
            }
            MapAction::ReadWriteExecuteUser => {
                entry.user_exec().read_write();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec().read_write();
            }
        }
    }

    fn set_l2_entry_rights(&self, entry: &mut L2DescriptorBlock) {
        entry.read_only().user_exec_never().priv_exec_never();

        match self {
            MapAction::None => {
                entry.no_access();
            }
            MapAction::ReadUser | MapAction::ReadKernel => (),
            MapAction::ReadWriteUser | MapAction::ReadWriteKernel => {
                entry.read_write();
            }
            MapAction::ReadExecuteKernel => {
                entry.priv_exec();
            }
            MapAction::ReadExecuteUser => {
                entry.user_exec();
            }
            MapAction::ReadWriteExecuteUser => {
                entry.user_exec().read_write();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec().read_write();
            }
        }
    }

    fn set_l1_entry_rights(&self, entry: &mut L1DescriptorBlock) {
        entry.read_only().user_exec_never().priv_exec_never();

        match self {
            MapAction::None => {
                entry.no_access();
            }
            MapAction::ReadUser | MapAction::ReadKernel => (),
            MapAction::ReadWriteUser | MapAction::ReadWriteKernel => {
                entry.read_write();
            }
            MapAction::ReadExecuteKernel => {
                entry.priv_exec();
            }
            MapAction::ReadExecuteUser => {
                entry.user_exec();
            }
            MapAction::ReadWriteExecuteUser => {
                entry.user_exec().read_write();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec().read_write();
            }
        }
    }

    // /// Transform MapAction into rights for 1 GiB page.
    // fn to_l1_rights(&self) -> u32 /* PDPTFlags */ {
    //     panic!("handle me!");
    //     // match self {
    //     //     None => PDPTFlags::empty(),
    //     //     ReadUser => PDPTFlags::XD | PDPTFlags::US,
    //     //     ReadKernel => PDPTFlags::XD,
    //     //     ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
    //     //     ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
    //     //     ReadExecuteUser => PDPTFlags::US,
    //     //     ReadExecuteKernel => PDPTFlags::empty(),
    //     //     ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
    //     //     ReadWriteExecuteKernel => PDPTFlags::RW,
    //     // }
    // }

    // /// Transform MapAction into rights for 2 MiB page.
    // fn to_l2_rights(&self) -> u32 /* PDFlags */ {
    //     panic!("handle me!");
    //     // match self {
    //     //     None => PDFlags::empty(),
    //     //     ReadUser => PDFlags::XD | PDFlags::US,
    //     //     ReadKernel => PDFlags::XD,
    //     //     ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
    //     //     ReadWriteKernel => PDFlags::RW | PDFlags::XD,
    //     //     ReadExecuteUser => PDFlags::US,
    //     //     ReadExecuteKernel => PDFlags::empty(),
    //     //     ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
    //     //     ReadWriteExecuteKernel => PDFlags::RW,
    //     // }
    // }

    // /// Transform MapAction into rights for 4KiB page.
    // fn to_l3_rights(&self) -> u32 /* PTFlags */ {
    //     panic!("handle me!");
    //     // match self {
    //     //     None => PTFlags::empty(),
    //     //     ReadUser => PTFlags::XD | PTFlags::US,
    //     //     ReadKernel => PTFlags::XD,
    //     //     ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
    //     //     ReadWriteKernel => PTFlags::RW | PTFlags::XD,
    //     //     ReadExecuteUser => PTFlags::US,
    //     //     ReadExecuteKernel => PTFlags::empty(),
    //     //     ReadWriteExecuteUser => PTFlags::RW | PTFlags::US,
    //     //     ReadWriteExecuteKernel => PTFlags::RW,
    //     // }
    // }
}

/// A VSpace allows to create and modify a (virtual) address space.
pub struct VSpaceAArch64<'a> {
    pub l0_table: &'a mut L0Table,
}

impl<'a> VSpaceAArch64<'a> {
    pub fn new() -> VSpaceAArch64<'a> {
        trace!("Allocate a L0Table (page-table root)");

        // configure the address space

        let l0: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        let l0_table = unsafe { &mut *paddr_to_uefi_vaddr(l0).as_mut_ptr::<L0Table>() };

        VSpaceAArch64 { l0_table: l0_table }
    }

    pub fn roottable(&self) -> u64 {
        self.l0_table as *const _ as u64
    }

    /// Constructs an identity map but with an offset added to the region.
    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: VAddr,
        pbase: PAddr,
        end: PAddr,
        rights: MapAction,
    ) {
        // on aarch64 we have the offset from the two ttbr registers.
        assert!((at_offset == VAddr::from(0x0)) | (at_offset == VAddr::from(arch::KERNEL_OFFSET)));
        self.map_identity(pbase, end, rights);
    }

    /// Constructs an identity map in this region of memory.
    ///
    /// # Example
    /// `map_identity(0x2000, 0x3000)` will map everything between 0x2000 and 0x3000 to
    /// physical address 0x2000 -- 0x3000.
    pub(crate) fn map_identity(&mut self, pbase: PAddr, end: PAddr, rights: MapAction) {
        let vbase = VAddr::from(pbase.as_u64());
        let size = (end - pbase).as_usize();
        debug!(
            "map_identity_with_offset {:#x} -- {:#x} -> {:#x} -- {:#x}",
            vbase,
            vbase + size,
            pbase,
            pbase + size
        );
        self.map_generic(vbase, (pbase, size), rights);
    }

    /// A pretty generic map function, it puts the physical memory range `pregion` with base and
    /// size into the virtual base at address `vbase`.
    ///
    /// The algorithm tries to allocate the biggest page-sizes possible for the allocations.
    /// We require that `vbase` and `pregion` values are all aligned to a page-size.
    /// TODO: We panic in case there is already a mapping covering the region (should return error).
    pub(crate) fn map_generic(&mut self, vbase: VAddr, pregion: (PAddr, usize), rights: MapAction) {
        let (pbase, psize) = pregion;
        assert_eq!(pbase % BASE_PAGE_SIZE, 0);
        assert_eq!(psize % BASE_PAGE_SIZE, 0);
        assert_eq!(vbase % BASE_PAGE_SIZE, 0);

        debug!(
            "map_generic {:#x} -- {:#x} -> {:#x} -- {:#x} {}",
            vbase,
            vbase + psize,
            pbase,
            pbase + psize,
            rights
        );

        let mut vaddr = vbase;
        let mut paddr = pbase;
        let mut size = psize;
        while vaddr < vbase + psize {
            // check if the l0 table entry has already a mapping
            if !self.l0_table.entry_at_vaddr(vaddr).is_valid() {
                let table = self.new_l1_table();
                self.l0_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l1_table = self
                .get_l1_table(self.l0_table.entry_at_vaddr(vaddr))
                .unwrap();

            // if both, vaddr and paddr are aligned, and we have enough remaining bytes
            // we can do a huge page mapping
            if vaddr.is_aligned(HUGE_PAGE_SIZE as u64)
                && paddr.is_aligned(HUGE_PAGE_SIZE as u64)
                && size >= HUGE_PAGE_SIZE
            {
                // perform the mapping
                let idx = L3Table::index(vaddr);
                while L3Table::index(vaddr) == idx && size >= HUGE_PAGE_SIZE {

                    let mut entry = L1DescriptorBlock::new();
                    rights.set_l1_entry_rights(&mut entry);
                    entry
                        .inner_shareable()
                        .outer_shareable()
                        .frame(paddr)
                        .valid();

                    l1_table.set_entry_at_vaddr(vaddr, L1Descriptor::from(entry));

                    size -= HUGE_PAGE_SIZE;
                    paddr = paddr + HUGE_PAGE_SIZE;
                    vaddr = vaddr + HUGE_PAGE_SIZE;
                }

                continue;
            }

            // check if the l0 table entry has already a mapping
            if !l1_table.entry_at_vaddr(vaddr).is_valid() {
                let table = self.new_l2_table();
                l1_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l2_table = self.get_l2_table(l1_table.entry_at_vaddr(vaddr)).unwrap();

            // if both, vaddr and paddr are aligned, and we have enough remaining bytes
            // we can do a huge page mapping
            if vaddr.is_aligned(LARGE_PAGE_SIZE as u64)
                && paddr.is_aligned(LARGE_PAGE_SIZE as u64)
                && size >= LARGE_PAGE_SIZE
            {
                // perform the mapping
                let idx = L2Table::index(vaddr);
                while L2Table::index(vaddr) == idx && size >= LARGE_PAGE_SIZE {

                    let mut entry = L2DescriptorBlock::new();
                    rights.set_l2_entry_rights(&mut entry);
                    entry
                        .inner_shareable()
                        .outer_shareable()
                        .frame(paddr)
                        .valid();

                    l2_table.set_entry_at_vaddr(vaddr, L2Descriptor::from(entry));

                    size -= LARGE_PAGE_SIZE;
                    paddr = paddr + LARGE_PAGE_SIZE;
                    vaddr = vaddr + LARGE_PAGE_SIZE;
                }

                continue;
            }

            // check if the l0 table entry has already a mapping
            if !l2_table.entry_at_vaddr(vaddr).is_valid() {
                let table = self.new_l3_table();
                l2_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l3_table = self.get_l3_table(l2_table.entry_at_vaddr(vaddr)).unwrap();

            let idx = L3Table::index(vaddr);
            while L3Table::index(vaddr) == idx && size >= BASE_PAGE_SIZE {
                // map it.
                let mut entry = L3Descriptor::new();
                rights.set_l3_entry_rights(&mut entry);
                entry
                    .inner_shareable()
                    .outer_shareable()
                    .frame(paddr)
                    .valid();

                l3_table.set_entry_at_vaddr(vaddr, entry);

                size -= BASE_PAGE_SIZE;
                paddr = paddr + BASE_PAGE_SIZE;
                vaddr = vaddr + BASE_PAGE_SIZE;
            }
        }

        if !self.l0_table.entry_at_vaddr(vbase).is_valid() {
            let table = self.new_l1_table();
            self.l0_table.set_entry_at_vaddr(vbase, table);
        }

        panic!("not yet implemented!");
    }

    /// A simple wrapper function for allocating just oen page.
    pub(crate) fn allocate_one_page() -> PAddr {
        panic!("not yet implemented!");
    }

    /// Does an allocation of physical memory where the base-address is a multiple of `align_to`.
    pub(crate) fn allocate_pages_aligned(
        how_many: usize,
        typ: uefi::table::boot::MemoryType,
        align_to: u64,
    ) -> PAddr {
        panic!("not yet implemented!");
    }

    /// Allocates a set of consecutive physical pages, using UEFI.
    ///
    /// Zeroes the memory we allocate (TODO: I'm not sure if this is already done by UEFI).
    /// Returns a `u64` containing the base to that.
    pub(crate) fn allocate_pages(how_many: usize, typ: uefi::table::boot::MemoryType) -> PAddr {
        panic!("not yet implemented!");
    }

    pub(crate) fn resolve_addr(&self, addr: VAddr) -> Option<PAddr> {
        panic!("not yet implemented!");
    }

    /// Back a region of virtual address space with
    /// allocated physical memory.
    ///
    ///  * The base should be a multiple of `BASE_PAGE_SIZE`.
    ///  * The size should be a multiple of `BASE_PAGE_SIZE`.
    #[allow(unused)]
    pub fn map(&mut self, base: VAddr, size: usize, rights: MapAction, palignment: u64) {
        panic!("not yet implemented!");
    }

    pub unsafe fn dump_table(&self) {
        panic!("not yet implemented!");
    }

    fn new_l3_table(&self) -> L2Descriptor {
        let l3: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        let l3_table = unsafe { &mut *paddr_to_uefi_vaddr(l3).as_mut_ptr::<L3Table>() };

        let mut l2_desc = L2DescriptorTable::new();
        l2_desc
            .table(l3_table)
            .priv_exec_table()
            .user_exec_never_table()
            .read_write_table()
            .valid();

        L2Descriptor::from(l2_desc)
    }

    fn new_l2_table(&self) -> L1Descriptor {
        let l2: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        let l2_table = unsafe { &mut *paddr_to_uefi_vaddr(l2).as_mut_ptr::<L2Table>() };

        let mut l1_desc = L1DescriptorTable::new();
        l1_desc
            .table(l2_table)
            .priv_exec_table()
            .user_exec_never_table()
            .read_write_table()
            .valid();

        L1Descriptor::from(l1_desc)
    }

    fn new_l1_table(&self) -> L0Descriptor {
        let l1: PAddr = memory::allocate_one_page(uefi::table::boot::MemoryType(KERNEL_PT));
        let l1_table = unsafe { &mut *paddr_to_uefi_vaddr(l1).as_mut_ptr::<L1Table>() };

        let mut l0_desc = L0Descriptor::new();
        l0_desc
            .table(l1_table)
            .priv_exec_table()
            .user_exec_never_table()
            .read_write_table()
            .valid();

        l0_desc
    }

    /// Resolve a PDEntry to a page table.
    fn get_l3_table<'b>(&self, entry: &L2Descriptor) -> Option<&'b mut L3Table> {
        if entry.is_valid() {
            unsafe {
                Some(transmute::<VAddr, &mut L3Table>(paddr_to_uefi_vaddr(
                    entry.get_paddr().unwrap(),
                )))
            }
        } else {
            None
        }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_l2_table<'b>(&self, entry: &L1Descriptor) -> Option<&'b mut L2Table> {
        if entry.is_valid() {
            unsafe {
                Some(transmute::<VAddr, &mut L2Table>(paddr_to_uefi_vaddr(
                    entry.get_paddr().unwrap(),
                )))
            }
        } else {
            None
        }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_l1_table<'b>(&self, entry: &L0Descriptor) -> Option<&'b mut L1Table> {
        if entry.is_valid() {
            unsafe {
                Some(transmute::<VAddr, &mut L1Table>(paddr_to_uefi_vaddr(
                    entry.get_paddr().unwrap(),
                )))
            }
        } else {
            None
        }
    }
}

/// Debug function to see what's currently in the UEFI address space.
#[allow(unused)]
fn dump_translation_root_register() {
    panic!("not yet implemented!");
}
