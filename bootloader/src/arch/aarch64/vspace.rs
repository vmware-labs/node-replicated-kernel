// Copyright © 2022 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::mem::transmute;
use core::{mem, slice};

use armv8::aarch64::vm::granule4k::*;

use uefi::prelude::*;
use uefi::table::boot::MemoryType;

use crate::kernel::*;
use crate::memory;
use crate::{allocate_pages, estimate_memory_map_size};

use crate::arch;

use crate::MapAction;

impl MapAction {
    fn set_l3_entry_rights(&self, entry: &mut L3Descriptor) {
        entry
            .read_only()
            .user_exec_never()
            .priv_exec_never()
            .set_attr_index(MemoryAttributes::NormalMemory);

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
            MapAction::DeviceMemoryKernel => {
                entry
                    .read_write()
                    .set_attr_index(MemoryAttributes::DeviceMemory);
            }
        }
    }

    fn set_l2_entry_rights(&self, entry: &mut L2DescriptorBlock) {
        entry
            .read_only()
            .user_exec_never()
            .priv_exec_never()
            .set_attr_index(MemoryAttributes::NormalMemory);

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
            MapAction::DeviceMemoryKernel => {
                entry
                    .read_write()
                    .set_attr_index(MemoryAttributes::DeviceMemory);
            }
        }
    }

    fn set_l1_entry_rights(&self, entry: &mut L1DescriptorBlock) {
        entry
            .read_only()
            .user_exec_never()
            .priv_exec_never()
            .set_attr_index(MemoryAttributes::NormalMemory);

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
            MapAction::DeviceMemoryKernel => {
                entry
                    .read_write()
                    .set_attr_index(MemoryAttributes::DeviceMemory);
            }
        }
    }
}

/// A VSpace allows to create and modify a (virtual) address space.
pub struct VSpaceAArch64<'a> {
    pub l0_table: &'a mut L0Table,
}

impl<'a> VSpaceAArch64<'a> {
    pub fn new() -> VSpaceAArch64<'a> {
        trace!("Allocate a L0Table (page-table root)");

        // configure the address space for el1
        configure_el1();

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
            "map_generic {:#x}..{:#x} -> {:#x}..{:#x} ({} kB) {}",
            vbase,
            vbase + psize,
            pbase,
            pbase + psize,
            psize >> 10,
            rights
        );

        let mut vaddr = vbase;
        let mut paddr = pbase;
        let mut size = psize;
        while vaddr < vbase + psize {
            debug!(
                "mapping {:#x}..{:#x} -> {:#x}..{:#x} ({} kB) {}",
                vaddr,
                vaddr + size,
                paddr,
                paddr + size,
                size >> 10,
                rights
            );

            // check if the l0 table entry has already a mapping
            if !self.l0_table.entry_at_vaddr(vaddr).is_valid() {
                debug!(
                    " - allocating a new l1 table (idx {})",
                    L0Table::index(vaddr)
                );
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
                let idx = L0Table::index(vaddr);
                while L0Table::index(vaddr) == idx && size >= HUGE_PAGE_SIZE {
                    debug!(
                        " - mapping 1G frame: {}.{} -> {:#x} ",
                        L0Table::index(vaddr),
                        L1Table::index(vaddr),
                        paddr
                    );
                    if l1_table.entry_at_vaddr(vaddr).is_block() {
                        panic!(
                            "l1table[{}.{}] contains already a block mapping: {:#x} -> {:#x}",
                            L0Table::index(vaddr),
                            L1Table::index(vaddr),
                            vaddr,
                            l1_table.entry_at_vaddr(vaddr).get_paddr()
                        );
                    }

                    if l1_table.entry_at_vaddr(vaddr).is_table() {
                        panic!(
                            "l2table[{}.{}] already contains a table mapping",
                            L0Table::index(vaddr),
                            L1Table::index(vaddr)
                        );
                    }

                    let mut entry = L1DescriptorBlock::new();
                    rights.set_l1_entry_rights(&mut entry);
                    entry
                        .inner_shareable()
                        .outer_shareable()
                        .set_attr_index(MemoryAttributes::NormalMemory)
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
                debug!(
                    " - allocating a new l2 table (idx {})",
                    L1Table::index(vaddr)
                );
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
                let idx = L1Table::index(vaddr);
                while L1Table::index(vaddr) == idx && size >= LARGE_PAGE_SIZE {
                    // debug!(
                    //     " - mapping 2M frame: {}.{}.{} -> {:#x} ",
                    //     L0Table::index(vaddr),
                    //     L1Table::index(vaddr),
                    //     L2Table::index(vaddr),
                    //     paddr
                    // );

                    if l2_table.entry_at_vaddr(vaddr).is_block() {
                        panic!(
                            "l2table[{}.{}.{}] contains already a block mapping: {:#x} -> {:#x}",
                            L0Table::index(vaddr),
                            L1Table::index(vaddr),
                            L2Table::index(vaddr),
                            vaddr,
                            l2_table.entry_at_vaddr(vaddr).get_paddr()
                        );
                    }

                    if l2_table.entry_at_vaddr(vaddr).is_table() {
                        panic!(
                            "l2table[{}.{}.{}] already contains a table mapping",
                            L0Table::index(vaddr),
                            L1Table::index(vaddr),
                            L2Table::index(vaddr)
                        );
                    }

                    let mut entry = L2DescriptorBlock::new();
                    rights.set_l2_entry_rights(&mut entry);
                    entry
                        .inner_shareable()
                        .outer_shareable()
                        .set_attr_index(MemoryAttributes::NormalMemory)
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
                debug!(
                    " - allocating a new l3 table (idx {})",
                    L2Table::index(vaddr)
                );
                let table = self.new_l3_table();
                l2_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l3_table = self.get_l3_table(l2_table.entry_at_vaddr(vaddr)).unwrap();

            let idx = L2Table::index(vaddr);
            while L2Table::index(vaddr) == idx && size >= BASE_PAGE_SIZE {
                trace!(
                    " - mapping 4k frame: {}.{}.{}.{} -> {:#x} ",
                    L0Table::index(vaddr),
                    L1Table::index(vaddr),
                    L2Table::index(vaddr),
                    L3Table::index(vaddr),
                    paddr
                );

                if l3_table.entry_at_vaddr(vaddr).is_valid() {
                    panic!(
                        "mapping already exists in l3table: {:#x} -> {:#x}",
                        vaddr,
                        l3_table.entry_at_vaddr(vaddr).get_paddr()
                    );
                }

                // map it.
                let mut entry = L3Descriptor::new();

                rights.set_l3_entry_rights(&mut entry);

                entry
                    .inner_shareable()
                    .outer_shareable()
                    .set_attr_index(MemoryAttributes::NormalMemory)
                    .frame(paddr)
                    .valid();

                l3_table.set_entry_at_vaddr(vaddr, entry);

                size -= BASE_PAGE_SIZE;
                paddr = paddr + BASE_PAGE_SIZE;
                vaddr = vaddr + BASE_PAGE_SIZE;
            }
        }
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

    pub(crate) fn resolve_addr(&self, vaddr: VAddr) -> Option<PAddr> {
        let l0_entry = self.l0_table.entry_at_vaddr(vaddr);
        if !l0_entry.is_valid() {
            return None;
        }

        let l1_table = self.get_l1_table(l0_entry).unwrap();
        let l1_entry = l1_table.entry_at_vaddr(vaddr);
        if !l1_entry.is_valid() {
            return None;
        }

        if l1_entry.is_block() {
            return l1_entry
                .get_frame()
                .map(|paddr| paddr + vaddr.huge_page_offset());
        }

        let l2_table = self.get_l2_table(l1_entry).unwrap();
        let l2_entry = l2_table.entry_at_vaddr(vaddr);
        if !l2_entry.is_valid() {
            return None;
        }

        if l2_entry.is_block() {
            return l2_entry
                .get_frame()
                .map(|paddr| paddr + vaddr.large_page_offset());
        }

        let l3_table = self.get_l3_table(l2_entry).unwrap();
        let l3_entry = l3_table.entry_at_vaddr(vaddr);

        if !l3_entry.is_valid() {
            return None;
        }

        return l3_entry
            .get_frame()
            .map(|paddr| paddr + vaddr.base_page_offset());
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
                    entry.get_paddr(),
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
                    entry.get_paddr(),
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
                    entry.get_paddr(),
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

/// Load the memory map into buffer (which is hopefully big enough).
pub fn map_physical_memory(st: &SystemTable<Boot>, kernel: &mut Kernel) {
    let (mm_size, _no_descs) = estimate_memory_map_size(st);
    let mm_paddr = allocate_pages(
        &st,
        mm_size / arch::BASE_PAGE_SIZE,
        MemoryType(UEFI_MEMORY_MAP),
    );
    let mm_slice: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(paddr_to_uefi_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size)
    };

    let (_key, desc_iter) = st
        .boot_services()
        .memory_map(mm_slice)
        .expect("Failed to retrieve UEFI memory map");

    for entry in desc_iter {
        if entry.phys_start == 0x0 {
            debug!("Don't map memory entry at physical zero? {:#?}", entry);
            continue;
        }

        // Compute physical base and bound for the region we're about to map
        let phys_range_start = arch::PAddr::from(entry.phys_start);
        let phys_range_end =
            arch::PAddr::from(entry.phys_start + entry.page_count * arch::BASE_PAGE_SIZE as u64);

        if phys_range_start.as_u64() <= 0xfee00000u64 && phys_range_end.as_u64() >= 0xfee00000u64 {
            debug!("{:?} covers APIC range, ignore for now.", entry);
            continue;
        }

        let rights: MapAction = match entry.ty {
            MemoryType::RESERVED => MapAction::None,
            MemoryType::LOADER_CODE => MapAction::ReadExecuteKernel,
            MemoryType::LOADER_DATA => MapAction::ReadWriteKernel,
            MemoryType::BOOT_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::BOOT_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::RUNTIME_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::RUNTIME_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::CONVENTIONAL => MapAction::ReadWriteExecuteKernel,
            MemoryType::UNUSABLE => MapAction::None,
            MemoryType::ACPI_RECLAIM => MapAction::ReadWriteKernel,
            MemoryType::ACPI_NON_VOLATILE => MapAction::ReadWriteKernel,
            MemoryType::MMIO => MapAction::DeviceMemoryKernel,
            MemoryType::MMIO_PORT_SPACE => MapAction::ReadWriteKernel,
            MemoryType::PAL_CODE => MapAction::ReadExecuteKernel,
            MemoryType::PERSISTENT_MEMORY => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_ELF) => MapAction::ReadKernel,
            MemoryType(KERNEL_PT) => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_STACK) => MapAction::ReadWriteKernel,
            MemoryType(UEFI_MEMORY_MAP) => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_ARGS) => MapAction::ReadKernel,
            MemoryType(MODULE) => MapAction::ReadKernel,
            _ => {
                error!("Unknown memory type, what should we do? {:#?}", entry);
                MapAction::None
            }
        };

        debug!(
            "Doing {:?} {:?} on {:#x} -- {:#x}",
            entry.ty, rights, phys_range_start, phys_range_end
        );

        if rights != MapAction::None {
            // kernel
            //     .vspace
            //     .map_identity(phys_range_start, phys_range_end, rights);

            if entry.ty == MemoryType::CONVENTIONAL
                // We're allowed to use these regions according to the spec  after we call ExitBootServices.
                // Also it can sometimes happens that the regions here switch from this type back
                // to conventional if we're not careful with memory allocations between the call
                // to `map_physical_memory` until getting the final memory mapped before booting..
                || entry.ty == MemoryType::BOOT_SERVICES_DATA
                || entry.ty == MemoryType::LOADER_DATA
                // These are regions we need to access in kernel space:
                || entry.ty == MemoryType(KERNEL_PT)
                || entry.ty == MemoryType(MODULE)
                || entry.ty == MemoryType(KERNEL_ARGS)
            {
                kernel.vspace.map_identity_with_offset(
                    arch::VAddr::from(arch::KERNEL_OFFSET as u64),
                    phys_range_start,
                    phys_range_end,
                    rights,
                );
            }
        }
    }
}
