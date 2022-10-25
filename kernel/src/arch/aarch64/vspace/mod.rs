// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use lazy_static::lazy_static;
use spin::Mutex;

use armv8::aarch64::vm::granule4k::L0Table;
use cortex_a::{asm::barrier, registers::*};
use fallible_collections::btree::BTreeMap;
use tock_registers::interfaces::{Readable, Writeable};

use crate::error::KError;
use crate::memory::paddr_to_kernel_vaddr;
use crate::memory::vspace::*; // detmem::DA,
use crate::memory::{Frame, PAddr, VAddr};

pub mod page_table;
use page_table::PageTable;

lazy_static! {
    /// A handle to the initial kernel address space (created for us by the
    /// bootloader) It contains a 1:1 mapping of
    ///  * all physical memory (above `KERNEL_BASE`)
    ///  * GIC
    pub(crate) static ref INITIAL_VSPACE: Mutex<PageTable> = {

        // The ttbr1_el1 register holds a physical address
        let l0_table_phys: PAddr = PAddr::from(TTBR1_EL1.get());

        // Safety `core::mem::transmute`:
        // - We know we can access this at kernel vaddr and it's a correctly
        // aligned+initialized L0Table pointer because of the informal contract
        // we have with the bootloader
        let l0_table = unsafe {
            core::mem::transmute::<VAddr, *mut L0Table>(paddr_to_kernel_vaddr(l0_table_phys))
        };

        // Safety `Box::from_raw`:
        // - This is a bit tricky since it technically got allocated by the
        //   bootloader
        // - However it should never get dropped anyways since we don't
        //   currently de-allocate the initial address space
        // - Only called once for the initial page-table (we loosely ensure
        //   this with lazy-static+putting this function inside of the
        //   lazy_static block)
        // - Memory layout: This is fine because with the wrong layout
        //   paging wouldn't work
        // - *Unsafety here*: if we ever drop this we'll be in trouble
        //   because it lead to some meta-data update with `slabmalloc`
        //   (free bits) which won't exist because this memory was never
        //   allocated with slabmalloc (maybe we can have a no_drop variant
        //   of PageTable?)
        let ptable = PageTable {
            l0_table: Box::into_pin(unsafe { Box::from_raw(l0_table) } ),
            da: None,
        };

        spin::Mutex::new(unsafe { ptable })
    };
}

pub(crate) struct VSpace {
    pub mappings: BTreeMap<VAddr, MappingInfo>,
    pub page_table: PageTable,
}

impl AddressSpace for VSpace {
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        panic!("not yet implemented")
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        panic!("not yet implemented")
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), KError> {
        panic!("not yet implemented")
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        panic!("not yet implemented")
    }

    fn adjust(&mut self, base: VAddr, new_rights: MapAction) -> Result<(VAddr, usize), KError> {
        panic!("not yet implemented")
    }
}
