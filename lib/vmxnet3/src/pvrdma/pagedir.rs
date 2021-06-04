// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

use alloc::alloc::{Allocator, Layout};
use alloc::collections::vec_deque::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use alloc::{alloc::AllocError, collections::TryReserveError};
use core::cmp;
use core::ops::Index;
use core::ptr::NonNull;

use log::info;

use custom_error::custom_error;
use driverkit::iomem::KERNEL_BASE;
use log::info;
use x86::current::paging::{IOAddr, PAddr, VAddr};

custom_error! {pub PVRDMAError
    PdirTooManyPages = "Too many pages for the pdir requested",
    PageIndexOutOfRange = "supplied index was out of range",
    InvalidMemoryReference = "No page set",
    OutOfMemory  = "Unable to allocate raw memory."
}

const PVRDMA_PDIR_SHIFT: u64 = 18;
const PVRDMA_PTABLE_SHIFT: u64 = 9;
// const PVRDMA_PAGE_DIR_DIR(x)		(((x) >> PVRDMA_PDIR_SHIFT) & 0x1)
// const PVRDMA_PAGE_DIR_TABLE(x)	(((x) >> PVRDMA_PTABLE_SHIFT) & 0x1ff)
// const PVRDMA_PAGE_DIR_PAGE(x)		((x) & 0x1ff)
const PVRDMA_PAGE_DIR_MAX_PAGES: u64 = (1 * 512 * 512);
const PVRDMA_PAGE_TABLE_MAX_PAGES: u64 = 512;

#[inline]
fn pvrdma_page_dir_table(n: u64) -> u64 {
    (n >> PVRDMA_PTABLE_SHIFT) & 0x1ff
}
#[inline]
fn pvrdma_page_dir_page(n: u64) -> u64 {
    (n & 0x1ff)
}

/// define the page size and the required alignment  XXX: shoud come form some definition?
const PVRDMA_PAGE_SIZE: usize = 4096;
const PVRDMA_PAGE_ALIGN: usize = 4096;

/// allocator that backs the tables
pub struct PVRDMATableAllocator {
    /// Layout established for this allocator.
    layout: Layout,
}

impl PVRDMATableAllocator {
    fn new(layout: Layout) -> Result<IOMemAllocator, IOMemError> {
        Ok(IOMemAllocator { layout: layout })
    }
}

unsafe impl Allocator for PVRDMATableAllocator {
    /// Allocates IO memory.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[IOAddr]>, AllocError> {
        // get the size to be allocated as a multiple of the initialized layout of the allocator

        unsafe {
            // do the actual allocation
            // TODO: refer to the OS allocator
            let ptr: *mut IOAddr = alloc::alloc::alloc_zeroed(layout);
            if ptr.is_null() {
                return Err(AllocError);
            }

            // wrap in in NonNull, remove option type
            let ptr_nonnull = NonNull::new(ptr).unwrap();

            // construct the NonNull slice for the return
            Ok(NonNull::slice_from_raw_parts(ptr_nonnull, layout.size()))
        }
    }

    /// Deallocates the previously allocated IO memory.
    unsafe fn deallocate(&self, ptr: NonNull<u64>, layout: Layout) {
        // XXX: check the layout matches the allocator here?
        let buf = ptr.as_ptr();
        // TODO: refer to the OS allocator
        alloc::alloc::dealloc(buf, layout);
    }
}

struct PVRDMATable {
    entries: Vec<IOAddr, PVRDMATableAllocator>,
    shadow: Vec<IOBuf>,
}

impl PVRDMATable {
    pub fn new(do_alloc: bool) -> Result<IOBuf, PVRDMAError> {
        let layout =
            Layout::from_size_align(PVRDMA_PAGE_SIZE, PVRDMA_PAGE_ALIGN).expect("Correct Layout");
        let allocator = IOMemAllocator::new(layout);

        let buf: Vec<IOAddr, IOMemAllocator> =
            Vec::with_capacity_in(layout.size(), allocator.unwrap());
        buf.expand();

        let mut shadow = Vec::<IOBuf>::new();
        shadow.reserve_exact(PVRDMA_PAGE_TABLE_MAX_PAGES);

        let mut table = {
            entries = buf;
            shadow = shadow
        };

        if (do_alloc) {
            for i in 0..npages {
                let page = IOBuf::new(layout).expect("Can't allocate memory for the pages?");
                table.insert(i, page);
            }
        }

        Ok(table)
    }

    pub fn insert(&mut self, idx: usize, buf: IOBuf) -> Result<PVRDMAError> {
        if idx >= self.shadow.capacity() {
            return PageIndexOutOfRange;
        }
        self.entries[idx] = buf.ioaddr();
        self.shadow[idx] = buf;
        Ok();
    }

    pub fn remove(&mut self, idx: usize, buf: IOBuf) -> Result<IOBuf, PVRDMAError> {
        if idx >= self.shadow.capacity() {
            return PageIndexOutOfRange;
        }

        self.entries[idx] = 0;
        match self.shadow.get(idx) {
            Some(x) => Ok(x), // is that element removed now?
            None => InvalidMemoryReference,
        }
    }
}

impl DmaObject for PVRDMATable {
    /// pysical of the table in main memory.
    fn paddr(&self) -> PAddr {
        PAddr::from(self.entries.as_ptr() as u64 - KERNEL_BASE)
    }

    /// Virtual address this buffer can be access by software.
    fn vaddr(&self) -> VAddr {
        VAddr::from(self.entries.as_ptr() as u64)
    }

    /// address as seen from the device
    fn ioaddr(&self) -> IOAddr {
        IOAddr::from(self.paddr().as_u64())
    }
}

/// represents the pvrdma page directory
struct PVRDMAPageDir {
    entries: Vec<u64, PVRDMATableAllocator>,
    shadow: Vec<PVRDMATable>,
}

impl PVRDMAPageDir {
    pub fn new(npages: usize, do_alloc: bool) -> Result<IOBuf, PVRDMAError> {
        if npages > PVRDMA_PAGE_DIR_MAX_PAGES {
            return PVRDMAError;
        }

        let layout =
            Layout::from_size_align(PVRDMA_PAGE_SIZE, PVRDMA_PAGE_ALIGN).expect("Correct Layout");
        let allocator = IOMemAllocator::new(layout);

        let entries: Vec<IOAddr, IOMemAllocator> =
            Vec::with_capacity_in(layout.size(), allocator.unwrap());
        entries.expand();

        // get the amount of tables
        let ntables = pvrdma_page_dir_table(npages - 1) + 1;

        let mut shadow = Vec::<PVRDMATable>::new();
        shadow.reserve_exact(ntables);

        for i in 0..ntables {
            shadow[i] = PVRDMATable::new(do_alloc).expect("Can't allocate memory for the tables");
            entries[i] = shadow[i].ioaddr();
        }
    }

    pub fn insert(&mut self, idx: usize, buf: IOBuf) {
        if idx > PVRDMA_PAGE_DIR_MAX_PAGES {
            return PageIndexOutOfRange;
        }
        let tableid = pvrdma_page_dir_table(idx);
        self.shadow[tableid].insert(buf)
    }

    pub fn remove(&mut self, idx: usize) -> Result<IOBuf, PVRDMAError> {
        if idx > PVRDMA_PAGE_DIR_MAX_PAGES {
            return PageIndexOutOfRange;
        }
        let tableid = pvrdma_page_dir_table(idx);
        self.shadow[tableid].remove
    }
}

impl DmaObject for PVRDMAPageDir {
    /// pysical of the table in main memory.
    fn paddr(&self) -> PAddr {
        PAddr::from(self.entries.as_ptr() as u64 - KERNEL_BASE)
    }

    /// Virtual address this buffer can be access by software.
    fn vaddr(&self) -> VAddr {
        VAddr::from(self.entries.as_ptr() as u64)
    }

    /// address as seen from the device
    fn ioaddr(&self) -> IOAddr {
        IOAddr::from(self.paddr().as_u64())
    }
}
