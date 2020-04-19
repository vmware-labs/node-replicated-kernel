//! A dummy vspace implementation for the unix platform.

use alloc::boxed::Box;
use core::pin::Pin;

use crate::memory::vspace::{AddressSpace, AddressSpaceError, MapAction, TlbFlushHandle};
use crate::memory::{Frame, PhysicalPageProvider};

use x86::bits64::paging::*;

pub struct VSpace {
    pub pml4: Pin<Box<PML4>>,
}

impl VSpace {
    pub fn new() -> VSpace {
        VSpace {
            pml4: Box::pin(
                [PML4Entry::new(PAddr::from(0x0u64), PML4Flags::empty()); PAGE_SIZE_ENTRIES],
            ),
        }
    }

    pub fn map_generic(
        &mut self,
        _vbase: VAddr,
        _pregion: (PAddr, usize),
        _rights: MapAction,
        _create_mappings: bool,
        _pager: &mut crate::memory::tcache::TCache,
    ) -> Result<(), AddressSpaceError> {
        Ok(())
    }
}

impl AddressSpace for VSpace {
    fn map_frame(
        &mut self,
        _base: VAddr,
        _frame: Frame,
        _action: MapAction,
        _pager: &mut dyn PhysicalPageProvider,
    ) -> Result<(), AddressSpaceError> {
        unimplemented!("map_frame");
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        unimplemented!("map_memory_requirements");
    }

    fn adjust(
        &mut self,
        _vaddr: VAddr,
        _rights: MapAction,
    ) -> Result<(VAddr, usize), AddressSpaceError> {
        unimplemented!("adjust");
    }

    fn resolve(&self, _vaddr: VAddr) -> Result<(PAddr, MapAction), AddressSpaceError> {
        unimplemented!("resolve");
    }

    fn unmap(&mut self, _vaddr: VAddr) -> Result<(TlbFlushHandle, Frame), AddressSpaceError> {
        unimplemented!("unmap");
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        panic!("Drop for VSpace!");
    }
}
