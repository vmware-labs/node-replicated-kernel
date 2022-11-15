// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::alloc::Allocator;
use core::alloc::Layout;
use core::mem::transmute;
use core::pin::Pin;
use core::ptr::NonNull;

use crate::memory::vspace::*;
use crate::memory::{PAddr, VAddr};
use armv8::aarch64::vm::granule4k::*;

use crate::error::KError;
use crate::memory::detmem::DA;
use crate::memory::Frame;

use crate::memory::vspace::MapAction;
use crate::memory::KERNEL_BASE;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr};

const PT_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE) };
// Safety (size not overflowing when rounding up is given with size == align):
static_assertions::const_assert!(BASE_PAGE_SIZE > 0); // align must not be zero
static_assertions::const_assert!(BASE_PAGE_SIZE.is_power_of_two()); // align must be a power of two

/// A modification operation on the PageTable.
enum Modify {
    /// Change rights of mapping to new MapAction.
    UpdateRights(MapAction),
    /// Remove frame from page-table.
    Unmap,
}

pub(crate) struct PageTable {
    pub l0_table: Pin<Box<L0Table>>,
    pub da: Option<DA>,
}

impl PageTable {
    /// Create a new address-space.
    ///
    /// Allocate an initial L0Table table for it.
    pub(crate) fn new(da: DA) -> Result<PageTable, KError> {
        let frame_ptr = da.allocate(PT_LAYOUT).unwrap();

        let vaddr = VAddr::from(frame_ptr.as_ptr() as *const u8 as u64);
        let paddr = crate::arch::memory::kernel_vaddr_to_paddr(vaddr);
        let mut frame = Frame::new(paddr, PT_LAYOUT.size(), 0);
        unsafe { frame.zero() };

        let l0_table = unsafe { &mut *paddr_to_kernel_vaddr(frame.base).as_mut_ptr::<L0Table>() };

        Ok(PageTable {
            l0_table: Box::into_pin(unsafe { Box::from_raw(l0_table) }),
            da: Some(da),
        })
    }

    pub(crate) fn root_table_address(&self) -> PAddr {
        let l0_vaddr = VAddr::from(&self.l0_table as *const _ as u64);
        kernel_vaddr_to_paddr(l0_vaddr)
    }

    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        let (pbase, psize) = pregion;
        assert_eq!(pbase % BASE_PAGE_SIZE, 0);
        assert_eq!(psize % BASE_PAGE_SIZE, 0);
        assert_eq!(vbase % BASE_PAGE_SIZE, 0);

        log::debug!(
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
            log::trace!(
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
                log::trace!(
                    " - allocating a new l1 table (idx {})",
                    L0Table::index(vaddr)
                );
                let table = self.new_l1_table();
                self.l0_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l1_table = self.get_l1_table_mut(self.l0_table.entry_at_vaddr(vaddr));

            // if both, vaddr and paddr are aligned, and we have enough remaining bytes
            // we can do a huge page mapping
            if vaddr.is_aligned(HUGE_PAGE_SIZE as u64)
                && paddr.is_aligned(HUGE_PAGE_SIZE as u64)
                && size >= HUGE_PAGE_SIZE
            {
                // perform the mapping
                let idx = L0Table::index(vaddr);
                while L0Table::index(vaddr) == idx && size >= HUGE_PAGE_SIZE {
                    log::trace!(
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
                        .accessed()
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
                log::trace!(
                    " - allocating a new l2 table (idx {})",
                    L1Table::index(vaddr)
                );
                let table = self.new_l2_table();
                l1_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l2_table = self.get_l2_table_mut(l1_table.entry_at_vaddr(vaddr));

            // if both, vaddr and paddr are aligned, and we have enough remaining bytes
            // we can do a huge page mapping
            if vaddr.is_aligned(LARGE_PAGE_SIZE as u64)
                && paddr.is_aligned(LARGE_PAGE_SIZE as u64)
                && size >= LARGE_PAGE_SIZE
            {
                // perform the mapping
                let idx = L1Table::index(vaddr);
                while L1Table::index(vaddr) == idx && size >= LARGE_PAGE_SIZE {
                    log::trace!(
                        " - mapping 2M frame: {}.{}.{} -> {:#x} ",
                        L0Table::index(vaddr),
                        L1Table::index(vaddr),
                        L2Table::index(vaddr),
                        paddr
                    );

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
                        .accessed()
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
                log::trace!(
                    " - allocating a new l3 table (idx {})",
                    L2Table::index(vaddr)
                );
                let table = self.new_l3_table();
                l2_table.set_entry_at_vaddr(vaddr, table);
            }

            // get the l1 table
            let l3_table = self.get_l3_table_mut(l2_table.entry_at_vaddr(vaddr));

            let idx = L2Table::index(vaddr);
            while L2Table::index(vaddr) == idx && size >= BASE_PAGE_SIZE {
                log::trace!(
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
                    .accessed()
                    .set_attr_index(MemoryAttributes::NormalMemory)
                    .frame(paddr)
                    .valid();

                l3_table.set_entry_at_vaddr(vaddr, entry);

                size -= BASE_PAGE_SIZE;
                paddr = paddr + BASE_PAGE_SIZE;
                vaddr = vaddr + BASE_PAGE_SIZE;
            }
        }
        Ok(())
    }

    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: PAddr,
        pbase: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        // on aarch64 we have the offset from the two ttbr registers.
        assert!((at_offset == PAddr::from(0x0u64)) | (at_offset == PAddr::from(KERNEL_BASE)));
        self.map_identity(pbase, size, rights)
    }

    /// Identity maps a given physical memory range [`base`, `base` + `size`]
    /// in the address space.
    pub(crate) fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        self.map_generic(VAddr::from(base.as_u64()), (base, size), rights, true)
    }

    /// Changes a mapping in the PageTable
    ///
    /// # Arguments
    ///  - `addr`: Identifies the mapping to be changed (can be anywhere in the mapped region)
    ///  - `action`: What action to perform: remove / update
    ///
    /// # Returns
    /// The affected virtual address region [`VAddr`, `VAddr` + usize), the underlying mapped
    /// physical address, and the old flags (or current flags if modify operation didn't change
    /// the flags).
    fn modify_generic<'a>(
        &'a mut self,
        addr: VAddr,
        action: Modify,
    ) -> Result<(VAddr, PAddr, usize, MapAction), KError> {
        panic!("not implemented");
    }

    fn alloc_page(&self) -> Frame {
        use core::alloc::Allocator;
        let frame_ptr = self.da.as_ref().map_or_else(
            || unsafe {
                let ptr = alloc::alloc::alloc(PT_LAYOUT);
                debug_assert!(!ptr.is_null());

                let nptr = NonNull::new_unchecked(ptr);
                NonNull::slice_from_raw_parts(nptr, PT_LAYOUT.size())
            },
            |da| da.allocate(PT_LAYOUT).unwrap(),
        );
        let vaddr = VAddr::from(frame_ptr.as_ptr() as *const u8 as u64);
        let paddr = crate::arch::memory::kernel_vaddr_to_paddr(vaddr);
        let mut frame = Frame::new(paddr, PT_LAYOUT.size(), 0);
        unsafe { frame.zero() };
        frame
    }

    /// Retrieves the relevant L1 table for a given virtual address `vbase`.
    ///
    /// Allocates the PDPT page if it doesn't exist yet.
    fn get_or_alloc_l1_table(&mut self, vbase: VAddr) -> &mut L1Table {
        let l0_entry = self.l0_table.entry_at_vaddr(vbase);
        if !l0_entry.is_valid() {
            let table = self.new_l1_table();
            self.l0_table.set_entry_at_vaddr(vbase, table);
        }
        let l0_entry = self.l0_table.entry_at_vaddr(vbase);
        self.get_l1_table_mut(l0_entry)
    }

    fn new_l3_table(&self) -> L2Descriptor {
        let frame = self.alloc_page();

        let l3_table = unsafe { &mut *paddr_to_kernel_vaddr(frame.base).as_mut_ptr::<L3Table>() };

        let mut l2_desc = L2DescriptorTable::new();
        l2_desc.table(l3_table).valid();

        assert!(l2_desc.get_paddr() == frame.base);
        L2Descriptor::from(l2_desc)
    }

    fn new_l2_table(&self) -> L1Descriptor {
        let frame = self.alloc_page();

        let l2_table = unsafe { &mut *paddr_to_kernel_vaddr(frame.base).as_mut_ptr::<L2Table>() };

        let mut l1_desc = L1DescriptorTable::new();
        l1_desc.table(l2_table).valid();

        assert!(l1_desc.get_paddr() == frame.base);
        L1Descriptor::from(l1_desc)
    }

    fn new_l1_table(&self) -> L0Descriptor {
        let frame = self.alloc_page();

        let l1_table = unsafe { &mut *paddr_to_kernel_vaddr(frame.base).as_mut_ptr::<L1Table>() };

        let mut l0_desc = L0Descriptor::new();
        l0_desc.table(l1_table).valid();

        assert!(l0_desc.get_paddr() == frame.base);
        L0Descriptor::from(l0_desc)
    }

    fn get_l3_table(&self, entry: L2Descriptor) -> &L3Table {
        assert!(entry.is_table());
        unsafe { transmute::<VAddr, &L3Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_l2_table(&self, entry: L1Descriptor) -> &L2Table {
        assert!(entry.is_table());
        unsafe { transmute::<VAddr, &L2Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_l1_table(&self, entry: L0Descriptor) -> &L1Table {
        assert!(entry.is_valid());
        unsafe { transmute::<VAddr, &L1Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }

    /// Resolve a PDEntry to a page table.
    fn get_l3_table_mut(&self, entry: L2Descriptor) -> &mut L3Table {
        assert!(entry.is_table());
        unsafe { transmute::<VAddr, &mut L3Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_l2_table_mut(&self, entry: L1Descriptor) -> &mut L2Table {
        assert!(entry.is_table());
        unsafe { transmute::<VAddr, &mut L2Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_l1_table_mut(&self, entry: L0Descriptor) -> &mut L1Table {
        assert!(entry.is_valid());
        unsafe { transmute::<VAddr, &mut L1Table>(paddr_to_kernel_vaddr(entry.get_paddr())) }
    }
}

impl Drop for PageTable {
    fn drop(&mut self) {
        panic!("implement me!");
    }
}

impl AddressSpace for PageTable {
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        // These assertion are checked with error returns in `VSpace`
        debug_assert!(frame.size() > 0);
        debug_assert_eq!(
            frame.base % frame.size(),
            0,
            "paddr should be aligned to page-size"
        );
        debug_assert_eq!(
            base % frame.size(),
            0,
            "vaddr should be aligned to page-size"
        );

        self.map_generic(base, (frame.base, frame.size()), action, true)
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        // TODO(correctness): Calculate this properly
        20
    }

    fn adjust(&mut self, vaddr: VAddr, rights: MapAction) -> Result<(VAddr, usize), KError> {
        if !vaddr.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }
        let (vaddr, _paddr, size, _old_rights) =
            self.modify_generic(vaddr, Modify::UpdateRights(rights))?;
        Ok((vaddr, size))
    }

    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr, MapAction), KError> {
        log::trace!("Resolving VADDR: {:#x}", vaddr);
        let l0_entry = self.l0_table.entry_at_vaddr(vaddr);
        if !l0_entry.is_valid() {
            log::trace!("-> L0Descriptor: Invalid ({:#x})", l0_entry.as_u64());
            return Err(KError::NotMapped);
        }

        log::trace!("-> L0Descriptor: {:#x}", l0_entry.as_u64());

        let l1_table = self.get_l1_table(l0_entry);
        let l1_entry = l1_table.entry_at_vaddr(vaddr);
        if !l1_entry.is_valid() {
            log::trace!("  -> L1Descriptor: Invalid ({:#x})", l1_entry.as_u64());
            return Err(KError::NotMapped);
        }

        if l1_entry.is_block() {
            log::trace!("  -> L1Descriptor: Block {:#x}", l1_entry.as_u64());
            let frame = l1_entry.get_frame().unwrap();

            return Ok((frame + vaddr.huge_page_offset(), MapAction::ReadExecuteUser));
        }

        log::trace!("  -> L1Descriptor: {:#x}", l1_entry.as_u64());

        let l2_table = self.get_l2_table(l1_entry);
        let l2_entry = l2_table.entry_at_vaddr(vaddr);
        if !l2_entry.is_valid() {
            log::trace!("    -> L2Descriptor: Invalid ({:#x})", l2_entry.as_u64());
            return Err(KError::NotMapped);
        }

        if l2_entry.is_block() {
            log::trace!("    -> L2Descriptor: Block {:#x}", l2_entry.as_u64());
            let frame = l2_entry.get_frame().unwrap();

            return Ok((
                frame + vaddr.large_page_offset(),
                MapAction::ReadExecuteUser,
            ));
        }

        log::trace!("    -> L2Descriptor: {:#x}", l2_entry.as_u64());

        let l3_table = self.get_l3_table(l2_entry);
        let l3_entry = l3_table.entry_at_vaddr(vaddr);

        if !l3_entry.is_valid() {
            log::trace!("      -> L3Descriptor: Invalid ({:#x})", l3_entry.as_u64());
            return Err(KError::NotMapped);
        }

        log::trace!("      -> L3Descriptor: Block {:#x}", l3_entry.as_u64());
        let frame = l3_entry.get_frame().unwrap();
        Ok((frame + vaddr.base_page_offset(), MapAction::ReadExecuteUser))
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        if !base.is_base_page_aligned() {
            return Err(KError::InvalidBase);
        }
        let (vaddr, paddr, size, _rights) = self.modify_generic(base, Modify::Unmap)?;
        // TODO(correctness+memory): we lose topology information here...
        Ok(TlbFlushHandle::new(vaddr, Frame::new(paddr, size, 0)))
    }
}

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
                entry.user_exec(); //.read_write();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec(); //.read_write();
            }
            MapAction::ReadWriteUserNoCache => {
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
                entry.user_exec();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec();
            }
            MapAction::ReadWriteUserNoCache => {
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
                entry.user_exec();
            }
            MapAction::ReadWriteExecuteKernel => {
                entry.priv_exec();
            }
            MapAction::ReadWriteUserNoCache => {
                entry
                    .read_write()
                    .set_attr_index(MemoryAttributes::DeviceMemory);
            }
        }
    }
}
