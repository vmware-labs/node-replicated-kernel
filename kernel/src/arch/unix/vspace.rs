//! A dummy vspace implementation for the unix platform.

use alloc::boxed::Box;
use core::fmt;
use core::pin::Pin;

use crate::alloc::string::ToString;
use crate::memory::vspace::{AddressSpaceError, MapAction, ResourceType};

use kpi::SystemCallError;
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

    pub fn map_identity(&mut self, base: VAddr, end: VAddr) {
        unreachable!("map_identity 0x{:x} -- 0x{:x}", base, end);
    }

    pub fn map(
        &mut self,
        base: VAddr,
        size: usize,
        rights: MapAction,
        palignment: u64,
    ) -> Result<(PAddr, usize), AddressSpaceError> {
        assert_eq!(base % BASE_PAGE_SIZE, 0, "base is not page-aligned");
        assert_eq!(size % BASE_PAGE_SIZE, 0, "size is not page-aligned");
        Ok((PAddr::from(base.as_u64()), size))
    }

    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        pager: &mut crate::memory::tcache::TCache,
    ) -> Result<(), AddressSpaceError> {
        Ok(())
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        panic!("Drop for VSpace!");
    }
}
