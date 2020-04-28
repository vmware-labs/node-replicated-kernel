use core::mem::transmute;
use core::ops::Range;
use core::pin::Pin;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use x86::bits64::paging::*;

mod debug;
pub mod page_table; /* TODO(encapsulation): This should be a private module but we break encapsulation in a few places */
#[cfg(test)]
mod test;

use crate::memory::vspace::*;
use crate::memory::{
    kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, Frame, PAddr, PhysicalPageProvider, VAddr,
};

use page_table::PageTable;

/// A modification operation on the VSpace.
enum Modify {
    /// Change rights of mapping to new MapAction.
    UpdateRights(MapAction),
    /// Remove frame from page-table.
    Unmap,
}

pub struct VSpace {
    pub mappings: BTreeMap<usize, MappingInfo>,
    pub page_table: PageTable,
}

impl AddressSpace for VSpace {
    fn map_frame(
        &mut self,
        base: VAddr,
        frame: Frame,
        action: MapAction,
    ) -> Result<(), AddressSpaceError> {
        self.page_table.map_frame(base, frame, action)
    }

    fn map_memory_requirements(base: VAddr, frames: &[Frame]) -> usize {
        // Implementation specific, the model does not require additional
        // memory for page-tables
        0
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError> {
        self.page_table.resolve(addr)
    }

    fn unmap(&mut self, base: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError> {
        self.page_table.unmap(base)
    }

    fn adjust(
        &mut self,
        base: VAddr,
        new_rights: MapAction,
    ) -> Result<(VAddr, usize), AddressSpaceError> {
        self.page_table.adjust(base, new_rights)
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        //panic!("Drop for VSpace!");
    }
}

impl VSpace {
    pub(crate) fn new() -> Self {
        VSpace {
            mappings: BTreeMap::new(),
            page_table: PageTable::new(),
        }
    }

    pub(crate) fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), AddressSpaceError> {
        let kcb = crate::kcb::get_kcb();
        let mut pager = kcb.mem_manager();
        self.page_table
            .map_identity(base, size, rights, &mut *pager)
    }

    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: PAddr,
        pbase: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), AddressSpaceError> {
        let kcb = crate::kcb::get_kcb();
        let mut pager = kcb.mem_manager();

        self.page_table
            .map_identity_with_offset(at_offset, pbase, size, rights, &mut *pager)
    }

    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        insert_mapping: bool,
        pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        self.page_table
            .map_generic(vbase, pregion, rights, insert_mapping, pager)
    }

    pub fn pml4_address(&self) -> PAddr {
        self.page_table.pml4_address()
    }
}
