// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::ops::Bound::*;

use fallible_collections::btree::BTreeMap;
use lazy_static::lazy_static;
use spin::Mutex;
use x86::current::paging::{PDFlags, PDPTFlags, PTFlags};

mod debug;

#[cfg(not(feature = "verified-code"))]
pub mod page_table; /* TODO(encapsulation): This should be a private module but we break encapsulation in a few places */

#[cfg(feature = "verified-code")]
#[path = "verified_page_table.rs"]
pub mod page_table;

#[cfg(feature = "verified-code")]
#[path = "page_table.rs"]
pub mod unverified_page_table;

#[cfg(test)]
mod test;

use crate::error::KError;
use crate::memory::{detmem::DA, vspace::*};
use crate::memory::{Frame, PAddr, VAddr};

use page_table::PageTable;

lazy_static! {
    /// A handle to the initial kernel address space (created for us by the
    /// bootloader) It contains a 1:1 mapping of
    ///  * all physical memory (above `KERNEL_BASE`)
    ///  * IO APIC and local APIC memory (after initialization has completed)
    pub(crate) static ref INITIAL_VSPACE: Mutex<PageTable> = {
        /// Return a struct to the currently installed page-tables so we can
        /// manipulate them (for example to map the APIC registers).
        ///
        /// This function is called during initialization. It will read the cr3
        /// register to find the physical address of the currently loaded PML4
        /// table which is constructed by the bootloader.
        ///
        /// # Safety
        /// - Will use the `cr3` register to find the page-table that is
        /// currently active in the MMU, so this will easily create aliased
        /// memory if not handled with care. The only time it makes sense to
        /// call this is to find the PageTable that the bootloader set up for
        /// us.
        unsafe fn find_current_ptable() -> PageTable {
            use x86::controlregs;
            use x86::current::paging::PML4;

            // The cr3 register holds a physical address
            let pml4: PAddr = PAddr::from(controlregs::cr3());

            // Safety `core::mem::transmute`:
            // - We know we can access this at kernel vaddr and it's a correctly
            // aligned+initialized PML4 pointer because of the informal contract
            // we have with the bootloader
            let pml4_table = core::mem::transmute::<PAddr, *mut PML4>(pml4);

            // Safety `from_pml4`:
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
            PageTable::from_pml4(pml4_table)
        }

        // Safety `find_current_ptable`:
        // - See comments above
        // - this global is initialized eagerly with `lazy_static::initialize`
        //   in `arch::_start` so we're sure we're "finding" the correct/initial
        //   page-table that was set-up by the bootloader.
        spin::Mutex::new(unsafe { find_current_ptable() })
    };
}

pub(crate) struct VSpace {
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
    pub(crate) fn new(da: DA) -> Result<Self, KError> {
        Ok(VSpace {
            mappings: BTreeMap::new(),
            page_table: PageTable::new(da)?,
        })
    }

    pub(crate) fn pml4_address(&self) -> PAddr {
        self.page_table.pml4_address()
    }
}

impl MapAction {
    /// Transform MapAction into rights for 1 GiB page.
    pub(crate) fn to_pdpt_rights(self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD | PDPTFlags::US,
            ReadKernel => PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteUserNoCache => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::US,
            ReadExecuteKernel => PDPTFlags::empty(),
            ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
            ReadWriteExecuteKernel => PDPTFlags::RW,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    pub(crate) fn to_pd_rights(self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD | PDFlags::US,
            ReadKernel => PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteUserNoCache => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteKernel => PDFlags::RW | PDFlags::XD,
            ReadExecuteUser => PDFlags::US,
            ReadExecuteKernel => PDFlags::empty(),
            ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
            ReadWriteExecuteKernel => PDFlags::RW,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    pub(crate) fn to_pt_rights(self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD | PTFlags::US,
            ReadKernel => PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteUserNoCache => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteKernel => PTFlags::RW | PTFlags::XD,
            ReadExecuteUser => PTFlags::US,
            ReadExecuteKernel => PTFlags::empty(),
            ReadWriteExecuteUser => PTFlags::RW | PTFlags::US,
            ReadWriteExecuteKernel => PTFlags::RW,
        }
    }
}

impl From<PTFlags> for MapAction {
    fn from(f: PTFlags) -> MapAction {
        use MapAction::*;
        let irrelevant_bits: PTFlags =
            PTFlags::PWT | PTFlags::A | PTFlags::D | PTFlags::G | PTFlags::PWT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PTFlags::P | PTFlags::US | PTFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PTFlags::XD | PTFlags::P {
            MapAction::ReadKernel
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::US | PTFlags::P | PTFlags::PCD {
            ReadWriteUserNoCache
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::US | PTFlags::P {
            ReadWriteUser
        } else if cleaned == PTFlags::RW | PTFlags::XD | PTFlags::P {
            ReadWriteKernel
        } else if cleaned == PTFlags::US | PTFlags::P {
            ReadExecuteUser
        } else if cleaned == PTFlags::RW | PTFlags::US | PTFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PTFlags::RW | PTFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PTFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
    }
}

impl From<PDFlags> for MapAction {
    fn from(f: PDFlags) -> MapAction {
        use MapAction::*;

        let irrelevant_bits =
            PDFlags::PWT | PDFlags::A | PDFlags::D | PDFlags::PS | PDFlags::G | PDFlags::PAT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PDFlags::P | PDFlags::US | PDFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PDFlags::XD | PDFlags::P {
            MapAction::ReadKernel
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::US | PDFlags::P | PDFlags::PCD {
            ReadWriteUserNoCache
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::US | PDFlags::P {
            ReadWriteUser
        } else if cleaned == PDFlags::RW | PDFlags::XD | PDFlags::P {
            ReadWriteKernel
        } else if cleaned == PDFlags::US | PDFlags::P {
            ReadExecuteUser
        } else if cleaned == PDFlags::RW | PDFlags::US | PDFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PDFlags::RW | PDFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PDFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
    }
}

impl From<PDPTFlags> for MapAction {
    fn from(f: PDPTFlags) -> MapAction {
        use MapAction::*;

        let irrelevant_bits: PDPTFlags = PDPTFlags::PWT
            | PDPTFlags::A
            | PDPTFlags::D
            | PDPTFlags::PS
            | PDPTFlags::G
            | PDPTFlags::PAT;

        let mut cleaned = f;
        cleaned.remove(irrelevant_bits);

        // Ugly if else (due to https://github.com/bitflags/bitflags/issues/201)
        if cleaned == PDPTFlags::P | PDPTFlags::US | PDPTFlags::XD {
            MapAction::ReadUser
        } else if cleaned == PDPTFlags::XD | PDPTFlags::P {
            MapAction::ReadKernel
        } else if cleaned
            == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US | PDPTFlags::P | PDPTFlags::PCD
        {
            ReadWriteUserNoCache
        } else if cleaned == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US | PDPTFlags::P {
            ReadWriteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::P {
            ReadWriteKernel
        } else if cleaned == PDPTFlags::US | PDPTFlags::P {
            ReadExecuteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::US | PDPTFlags::P {
            ReadWriteExecuteUser
        } else if cleaned == PDPTFlags::RW | PDPTFlags::P {
            ReadWriteExecuteKernel
        } else if cleaned == PDPTFlags::P {
            ReadExecuteKernel
        } else {
            None
        }
    }
}
