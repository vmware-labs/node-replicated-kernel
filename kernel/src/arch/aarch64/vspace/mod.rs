// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use lazy_static::lazy_static;
use spin::Mutex;

use fallible_collections::btree::BTreeMap;

use crate::error::KError;
use crate::memory::vspace::*; // detmem::DA,
use crate::memory::{Frame, PAddr, VAddr};

pub mod page_table;
use page_table::PageTable;

lazy_static! {
    /// A handle to the initial kernel address space (created for us by the
    /// bootloader) It contains a 1:1 mapping of
    ///  * all physical memory (above `KERNEL_BASE`)
    ///  * IO APIC and local APIC memory (after initialization has completed)
    pub(crate) static ref INITIAL_VSPACE: Mutex<PageTable> = {
        panic!("not yet implemented")
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
