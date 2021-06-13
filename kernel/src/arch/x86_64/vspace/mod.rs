// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::ops::Bound::*;

use fallible_collections::btree::BTreeMap;

mod debug;
pub mod page_table; /* TODO(encapsulation): This should be a private module but we break encapsulation in a few places */
#[cfg(test)]
mod test;

use crate::error::KError;
use crate::memory::vspace::*;
use crate::memory::{Frame, PAddr, VAddr};

use page_table::PageTable;

pub struct VSpace {
    pub mappings: BTreeMap<VAddr, MappingInfo>,
    pub page_table: PageTable,
}

impl AddressSpace for VSpace {
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        if frame.size() == 0 {
            return Err(KError::InvalidFrame);
        }
        if frame.base % frame.size() != 0 {
            // physical address should be aligned to page-size
            return Err(KError::InvalidFrame);
        }
        if base % frame.size() != 0 {
            // virtual addr should be aligned to page-size
            return Err(KError::InvalidBase);
        }

        let tomap_range = base.as_usize()..base.as_usize() + frame.size;

        // Check all mapping in that region to see if we can allow this map:
        // Start with greatest VAddr that is smaller than base
        for (&existing_base, existing_mapping) in self
            .mappings
            .range((Unbounded, Excluded(VAddr::from(tomap_range.end))))
            .rev()
        {
            let existing_map_range = existing_mapping.vrange(existing_base);
            if existing_map_range.end <= tomap_range.start {
                // We reached the end of relevant mappings
                break;
            }

            if existing_base == base
                && existing_mapping.frame.base == frame.base
                && existing_mapping.frame.size <= frame.size
                && existing_mapping.rights == action
            {
                return Ok(());
            } else {
                return Err(KError::AlreadyMapped {
                    base: VAddr::from(existing_base),
                });
            }
        }

        self.mappings
            .try_insert(base, MappingInfo::new(frame, action))?;
        self.page_table.map_frame(base, frame, action)
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        // Implementation specific, the model does not require additional
        // memory for page-tables
        0
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), KError> {
        self.page_table.resolve(addr)
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        for (&existing_base, existing_mapping) in
            self.mappings.range((Unbounded, Included(base))).rev()
        {
            let existing_map_range = existing_mapping.vrange(existing_base);
            if existing_map_range.contains(&base.as_usize()) {
                break;
            } else {
                return Err(KError::NotMapped);
            }
        }

        let r = self.page_table.unmap(base)?;
        let rbt = self.mappings.remove(&r.vaddr);
        debug_assert!(rbt.is_some());
        Ok(r)
    }

    fn adjust(&mut self, base: VAddr, new_rights: MapAction) -> Result<(VAddr, usize), KError> {
        let r = self.page_table.adjust(base, new_rights)?;
        let mapping = self.mappings.get_mut(&r.0).ok_or(KError::NotMapped)?;
        mapping.rights = new_rights;
        Ok(r)
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        //panic!("Drop for VSpace!");
    }
}

impl VSpace {
    pub(crate) fn new() -> Result<Self, KError> {
        Ok(VSpace {
            mappings: BTreeMap::new(),
            page_table: PageTable::new()?,
        })
    }

    pub fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        self.page_table.map_identity(base, size, rights)
    }

    pub fn pml4_address(&self) -> PAddr {
        self.page_table.pml4_address()
    }
}
