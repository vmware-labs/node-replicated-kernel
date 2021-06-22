// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! Page directory for PVRDMA

#![allow(non_camel_case_types)]

use core::alloc::{AllocError, Allocator};
use core::ptr::NonNull;

use alloc::alloc::Layout;
use alloc::boxed::Box;
use alloc::vec::Vec;

use fallible_collections::FallibleVecGlobal;

use driverkit::iomem::{DmaAllocator, DmaObject, KERNEL_BASE};
use x86::current::paging::{IOAddr, PAddr, VAddr, BASE_PAGE_SIZE};

use super::PVRDMAError;
use crate::BoundedUSize;

const PVRDMA_PDIR_SHIFT: usize = 18;
const PVRDMA_PTABLE_SHIFT: usize = 9;
const PVRDMA_PAGE_DIR_MAX_PAGES: usize = 512 * 512;
const PVRDMA_PAGE_DIR_MAX_TABLES: usize = 512;
const PVRDMA_PAGE_TABLE_MAX_PAGES: usize = 512;

const fn pvrdma_page_dir_dir(n: usize) -> usize {
    (n >> PVRDMA_PDIR_SHIFT) & 0x1
}

const fn pvrdma_page_dir_table(n: usize) -> usize {
    (n >> PVRDMA_PTABLE_SHIFT) & (PVRDMA_PAGE_TABLE_MAX_PAGES - 1)
}

/// const PVRDMA_PAGE_DIR_PAGE(x)		((x) & 0x1ff)
const fn pvrdma_page_dir_page(n: usize) -> usize {
    n & (PVRDMA_PAGE_TABLE_MAX_PAGES - 1)
}

const PVRDMA_PAGE_SIZE: usize = BASE_PAGE_SIZE;
const PVRDMA_PAGE_ALIGN: usize = BASE_PAGE_SIZE;

/// Layout for allocated pages (and tables)
const PAGE_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(PVRDMA_PAGE_SIZE, PVRDMA_PAGE_ALIGN) };
// Safety:
static_assertions::const_assert!(PVRDMA_PAGE_SIZE == PVRDMA_PAGE_ALIGN); // size not overflowing when rounding up
static_assertions::const_assert!(PVRDMA_PAGE_SIZE > 0); // align must not be zero
static_assertions::const_assert!(PVRDMA_PAGE_ALIGN.is_power_of_two()); // align must be a power of two

/// Page-table type (contains IOAddrs for a series of pages)
type PTable = [IOAddr; PVRDMA_PAGE_TABLE_MAX_PAGES];
static_assertions::assert_eq_size!(PDir, [u8; 4096]);

/// Table type
pub struct Table(Box<PTable, DmaAllocator>);

impl Table {
    fn new(allocator: DmaAllocator) -> Result<Self, AllocError> {
        Ok(Table(Box::try_new_in(
            [IOAddr::zero(); PVRDMA_PAGE_TABLE_MAX_PAGES],
            allocator,
        )?))
    }
}

impl DmaObject for Table {
    fn paddr(&self) -> PAddr {
        PAddr::from(self.0.as_ptr() as u64 - KERNEL_BASE)
    }

    fn vaddr(&self) -> VAddr {
        VAddr::from(self.0.as_ptr() as u64)
    }

    fn ioaddr(&self) -> IOAddr {
        IOAddr::from(self.paddr().as_u64())
    }
}

/// Page-dir type (contains IOAddrs of PTables)
type PDir = [IOAddr; PVRDMA_PAGE_TABLE_MAX_PAGES];
static_assertions::assert_eq_size!(PDir, [u8; 4096]);

/// Represents the pvrdma page directory
pub struct pvrdma_page_dir {
    /// State to access tables (e.g., the dir members) on the CPU.
    tables: Vec<Table>,

    /// The directory of tables (IO addresses of tables handed to the device).
    dir: Box<PDir, DmaAllocator>,

    /// Pages accessible by the CPU (that are stored inside PTables)
    pub pages: Vec<NonNull<[u8]>>,

    /// Underlying allocator for DMA accessible memory.
    allocator: DmaAllocator,
}

impl pvrdma_page_dir {
    pub fn new(npages: usize, alloc_pages: bool) -> Result<Self, PVRDMAError> {
        let allocator = DmaAllocator::default();

        let npages = BoundedUSize::<0, PVRDMA_PAGE_DIR_MAX_PAGES>::new(npages);
        let mut pages = Vec::try_with_capacity(*npages)?;

        let ntables = pvrdma_page_dir_table(*npages - 1) + 1;
        debug_assert!(ntables <= PVRDMA_PAGE_DIR_MAX_TABLES);

        let mut dir = Box::try_new_in([IOAddr::zero(); PVRDMA_PAGE_DIR_MAX_TABLES], allocator)?;
        let mut tables = Vec::try_with_capacity(ntables)?;
        for i in 0..ntables {
            tables.push(Table::new(allocator)?);
            dir[i] = tables[i].ioaddr();
        }

        if alloc_pages {
            for _i in 0..*npages {
                let page = allocator.allocate(PAGE_LAYOUT)?;
                pages.push(page);
            }
        }

        Ok(Self {
            allocator,
            dir,
            tables,
            pages,
        })
    }

    pub fn table(&self, idx: usize) -> &Table {
        debug_assert!(idx < PVRDMA_PAGE_DIR_MAX_PAGES);
        let tidx = pvrdma_page_dir_table(idx);
        &self.tables[tidx]
    }

    pub fn get_dma(&self, idx: usize) -> IOAddr {
        debug_assert!(idx < PVRDMA_PAGE_DIR_MAX_PAGES);
        let pidx = pvrdma_page_dir_page(idx);
        self.table(idx).0[pidx]
    }

    pub fn insert_dma() {
        unimplemented!()
    }

    pub fn insert_umem() {
        unimplemented!()
    }

    pub fn insert_page_list() {
        unimplemented!()
    }
}

impl Drop for pvrdma_page_dir {
    fn drop(&mut self) {
        for page in self.pages.iter() {
            unsafe {
                self.allocator
                    .deallocate(page.as_non_null_ptr(), PAGE_LAYOUT)
            };
        }
    }
}

impl DmaObject for pvrdma_page_dir {
    fn paddr(&self) -> PAddr {
        PAddr::from(self.dir.as_ptr() as u64 - KERNEL_BASE)
    }

    fn vaddr(&self) -> VAddr {
        VAddr::from(self.dir.as_ptr() as u64)
    }

    fn ioaddr(&self) -> IOAddr {
        IOAddr::from(self.paddr().as_u64())
    }
}
