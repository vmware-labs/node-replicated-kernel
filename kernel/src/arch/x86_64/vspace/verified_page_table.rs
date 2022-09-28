// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(warnings, dead_code)]

use alloc::boxed::Box;
use core::alloc::Layout;
use core::mem::transmute;
use core::pin::Pin;
use core::ptr::NonNull;

use crate::arch::memory::KERNEL_BASE;
use log::{debug, trace};
use verified_pt;
use x86::bits64::paging::*;

use crate::error::KError;
use crate::memory::detmem::DA;
use crate::memory::vspace::*;
use crate::memory::{kernel_vaddr_to_paddr, paddr_to_kernel_vaddr, Frame, PAddr, VAddr};

pub(super) use super::unverified_page_table::Modify;
pub(crate) use super::unverified_page_table::ReadOnlyPageTable;
pub(super) use super::unverified_page_table::PT_LAYOUT;

pub(crate) struct PageTable {
    pub(crate) inner: verified_pt::impl_u::l2_impl::PageTable,
}

unsafe impl Sync for PageTable {}
unsafe impl Send for PageTable {}

impl Drop for PageTable {
    fn drop(&mut self) {}
}

impl AddressSpace for PageTable {
    fn map_frame(&mut self, base: VAddr, frame: Frame, action: MapAction) -> Result<(), KError> {
        let pte = verified_pt::definitions_t::PageTableEntryExec {
            frame: verified_pt::definitions_t::MemRegionExec {
                base: frame.base.as_usize(),
                size: frame.size,
            },
            flags: verified_pt::definitions_t::Flags {
                is_writable: action.is_writable(),
                is_supervisor: action.is_kernel(),
                disable_execute: !action.is_executable(),
            },
        };

        let res = self.inner.map_frame(base.as_usize(), pte);
        match res {
            verified_pt::definitions_t::MapResult::Ok => Ok(()),
            verified_pt::definitions_t::MapResult::ErrOverlap => Err(KError::AlreadyMapped {
                base: VAddr::from(0x0),
            }),
        }
    }

    fn map_memory_requirements(_base: VAddr, _frames: &[Frame]) -> usize {
        // TODO(correctness): Calculate this properly
        20
    }

    fn adjust(&mut self, vaddr: VAddr, rights: MapAction) -> Result<(VAddr, usize), KError> {
        let tlb_flush_handle = self.unmap(vaddr)?;
        self.map_frame(vaddr, tlb_flush_handle.frame, rights)?;
        Ok((vaddr, tlb_flush_handle.frame.size))
    }

    fn resolve(&self, addr: VAddr) -> Result<(PAddr, MapAction), KError> {
        let res = self.inner.resolve(addr.as_usize());
        match res {
            verified_pt::pervasive::result::Result::Ok((pa, flags)) => {
                let ptflags = PTFlags::from_bits_truncate(flags);
                Ok((PAddr::from(pa), ptflags.into()))
            }
            verified_pt::pervasive::result::Result::Err(_) => Err(KError::NotMapped),
        }
    }

    fn unmap(&mut self, base: VAddr) -> Result<TlbFlushHandle, KError> {
        let res = self.inner.unmap(base.as_usize());
        match res {
            verified_pt::definitions_t::UnmapResult::Ok(pa, size, flags) => {
                let ptflags = PTFlags::from_bits_truncate(flags);
                let node = 0x0; // TODO
                Ok(TlbFlushHandle::new(
                    VAddr::from(base),
                    Frame::new(pa.into(), size, 0),
                ))
            }
            verified_pt::definitions_t::UnmapResult::ErrNoSuchMapping => Err(KError::NotMapped),
        }
    }
}

impl PageTable {
    /// Create a new address-space.
    ///
    /// Allocate an initial PML4 table for it.
    pub(crate) fn new(da: DA) -> Result<PageTable, KError> {
        unsafe {
            let pml4 = PageTable::alloc_frame_with_da(&da);
            Ok(PageTable {
                inner: verified_pt::impl_u::l2_impl::PageTable {
                    memory: verified_pt::mem_t::PageTableMemory {
                        ptr: KERNEL_BASE as *mut u64,
                        pml4: pml4.base.as_usize(),
                        pt_allocator: Box::new(move || {
                            PageTable::alloc_frame_with_da(&da).base.as_usize()
                        }),
                    },
                    arch: verified_pt::definitions_t::x86_arch_exec(),
                    ghost_pt: (),
                },
            })
        }
    }

    /// Create a new address space given a raw pointer to a PML4 table.
    ///
    /// # Safety
    /// - tldr: never use this function (use [`PageTable::new`] instead), except
    ///   for where we construct a `PageTable` from the initial cr3 value that
    ///   the bootloader gave us.
    /// - Pretty unsafe needs to be unaliased and valid PML4 table (including
    ///   everything the table points to).
    /// - THe `pml4_table` is converted to a Box using [`Box::from_raw`] so
    ///   either should make sure that the `Self` lives forever or the PML4 came
    ///   from a [`Box::into_raw`] call).
    pub(super) unsafe fn from_pml4(pml4_table: *mut PML4) -> Self {
        PageTable {
            inner: verified_pt::impl_u::l2_impl::PageTable {
                memory: verified_pt::mem_t::PageTableMemory {
                    ptr: 0x0 as *mut u64,
                    pml4: pml4_table as usize,
                    pt_allocator: Box::new(|| PageTable::alloc_frame_no_da().base.as_usize()),
                },
                arch: verified_pt::definitions_t::x86_arch_exec(),
                ghost_pt: (),
            },
        }
    }

    pub(crate) fn pml4_address(&self) -> PAddr {
        self.inner.memory.pml4.into()
    }

    pub(crate) fn pml4<'a>(&'a self) -> Pin<&'a PML4> {
        unsafe {
            let pml4_vaddr: VAddr = self.inner.memory.pml4.into();
            let pml4: &'a PML4 = &*pml4_vaddr.as_ptr::<PML4>();

            Pin::new_unchecked(pml4)
        }
    }

    pub(crate) fn pml4_mut<'a>(&'a mut self) -> Pin<&'a mut PML4> {
        unsafe {
            let pml4_vaddr: VAddr = self.inner.memory.pml4.into();
            let pml4: &'a mut PML4 = &mut *pml4_vaddr.as_mut_ptr::<PML4>();

            Pin::new_unchecked(pml4)
        }
    }

    pub(crate) fn patch_kernel_mappings(&mut self, kvspace: &Self) {
        // Install the kernel mappings
        // TODO(efficiency): These should probably be global mappings
        // TODO(broken): Big (>= 2 MiB) allocations should be inserted here too
        // TODO(ugly): Find a better way to express this mess

        for i in 128..=135 {
            let kernel_pml_entry = kvspace.pml4()[i];
            trace!("Patched in kernel mappings at {:?}", kernel_pml_entry);
            self.pml4_mut()[i] = kernel_pml_entry;
        }
    }

    /// Constructs an identity map but with an offset added to the region.
    ///
    /// This can be useful for example to map physical memory above `KERNEL_BASE`.
    pub(crate) fn map_identity_with_offset(
        &mut self,
        at_offset: PAddr,
        pbase: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        assert!(at_offset.is_base_page_aligned());
        assert!(pbase.is_base_page_aligned());
        assert_eq!(size % BASE_PAGE_SIZE, 0, "Size not a multiple of page-size");

        let vbase = VAddr::from_u64((at_offset + pbase).as_u64());
        debug!(
            "map_identity_with_offset {:#x} -- {:#x} -> {:#x} -- {:#x}",
            vbase,
            vbase + size,
            pbase,
            pbase + size
        );

        let lps = size / LARGE_PAGE_SIZE;
        let bps = (size - (lps * LARGE_PAGE_SIZE)) / BASE_PAGE_SIZE;
        for i in 0..lps {
            let vbase_i = VAddr::from_u64((at_offset + pbase + i * LARGE_PAGE_SIZE).as_u64());
            let pbase_i = pbase + i * LARGE_PAGE_SIZE;

            self.map_frame(vbase_i, Frame::new(pbase_i, LARGE_PAGE_SIZE, 0), rights)?;
        }

        for i in 0..bps {
            let vbase_i = VAddr::from_u64(
                (at_offset + pbase + lps * LARGE_PAGE_SIZE + i * BASE_PAGE_SIZE).as_u64(),
            );
            let pbase_i = pbase + lps * LARGE_PAGE_SIZE + i * BASE_PAGE_SIZE;

            self.map_frame(vbase_i, Frame::new(pbase_i, BASE_PAGE_SIZE, 0), rights)?;
        }

        Ok(())
    }

    /// Identity maps a given physical memory range [`base`, `base` + `size`]
    /// in the address space.
    pub(crate) fn map_identity(
        &mut self,
        base: PAddr,
        size: usize,
        rights: MapAction,
    ) -> Result<(), KError> {
        self.map_identity_with_offset(PAddr::from(0x0), base, size, rights)
    }

    fn alloc_frame_with_da(da: &DA) -> Frame {
        use core::alloc::Allocator;
        let frame_ptr = da.allocate(PT_LAYOUT).unwrap();

        let vaddr = VAddr::from(frame_ptr.as_ptr() as *const u8 as u64);
        let paddr = crate::arch::memory::kernel_vaddr_to_paddr(vaddr);
        let mut frame = Frame::new(paddr, PT_LAYOUT.size(), 0);

        unsafe { frame.zero() };
        frame
    }

    fn alloc_frame_no_da() -> Frame {
        use core::alloc::Allocator;
        let frame_ptr = unsafe {
            let ptr = alloc::alloc::alloc(PT_LAYOUT);
            debug_assert!(!ptr.is_null());

            let nptr = NonNull::new_unchecked(ptr);
            NonNull::slice_from_raw_parts(nptr, PT_LAYOUT.size())
        };

        let vaddr = VAddr::from(frame_ptr.as_ptr() as *const u8 as u64);
        let paddr = crate::arch::memory::kernel_vaddr_to_paddr(vaddr);
        let mut frame = Frame::new(paddr, PT_LAYOUT.size(), 0);

        unsafe { frame.zero() };
        frame
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt(&self, entry: PDEntry) -> &PT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd(&self, entry: PDPTEntry) -> &PD {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt(&self, entry: PML4Entry) -> &PDPT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDEntry to a page table.
    fn get_pt_mut(&mut self, entry: PDEntry) -> &mut PT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PT>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PDPTEntry to a page directory.
    fn get_pd_mut(&mut self, entry: PDPTEntry) -> &mut PD {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PD>(paddr_to_kernel_vaddr(entry.address())) }
    }

    /// Resolve a PML4Entry to a PDPT.
    fn get_pdpt_mut(&mut self, entry: PML4Entry) -> &mut PDPT {
        assert_ne!(entry.address(), PAddr::zero());
        unsafe { transmute::<VAddr, &mut PDPT>(paddr_to_kernel_vaddr(entry.address())) }
    }
}
