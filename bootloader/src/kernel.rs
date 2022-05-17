// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Implements the necessary functionality to load the ELF image in machine memory.
use crate::alloc::vec::Vec;

use bootloader_shared::TlsInfo;
use elfloader::{self, ElfLoaderErr};
use x86::bits64::paging::*;

use crate::vspace::*;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

macro_rules! is_page_aligned {
    ($num:expr) => {
        $num % BASE_PAGE_SIZE as u64 == 0
    };
}

/// UEFI memory region type for ELF data allocation.
pub const KERNEL_ELF: u32 = 0x80000001;

/// UEFI memory region type for kernel page-tables.
pub const KERNEL_PT: u32 = 0x80000002;

/// UEFI memory region type for the kernel stack.
pub const KERNEL_STACK: u32 = 0x80000003;

/// UEFI memory region type for the memory map.
pub const UEFI_MEMORY_MAP: u32 = 0x80000004;

/// UEFI memory region type for arguments passed to the kernel.
pub const KERNEL_ARGS: u32 = 0x80000005;

/// UEFI memory region type for arguments passed to the kernel.
pub const MODULE: u32 = 0x80000006;

/// 512 GiB are that many bytes.
pub const GIB_512: usize = 512 * 512 * 512 * 0x1000;

/// Translate between PAddr and VAddr
pub(crate) fn paddr_to_uefi_vaddr(paddr: PAddr) -> VAddr {
    return VAddr::from(paddr.as_u64());
}

/// Translate between PAddr and VAddr
pub(crate) fn paddr_to_kernel_vaddr(paddr: PAddr) -> VAddr {
    return VAddr::from(KERNEL_OFFSET + paddr.as_usize());
}

/// The starting address of the kernel address space
///
/// All physical mappings are identity mapped with KERNEL_OFFSET as
/// displacement.
pub const KERNEL_OFFSET: usize = 1 << 46;

/// This struct stores meta-data required to construct
/// an address space for the kernel and relocate the
/// kernel ELF binary into it.
///
/// It also implements the ElfLoader trait.
pub struct Kernel<'a> {
    pub offset: VAddr,
    pub mapping: Vec<(VAddr, usize, u64, MapAction)>,
    pub vspace: VSpace<'a>,
    pub tls: Option<TlsInfo>,
}

impl<'a> elfloader::ElfLoader for Kernel<'a> {
    /// Makes sure the process vspace is backed for the regions
    /// reported by the elf loader as loadable.
    ///
    /// Our strategy is to first figure out how much space we need,
    /// then allocate a single chunk of physical memory and
    /// map the individual pieces of it with different access rights.
    /// This has the advantage that our kernel address space is
    /// all a very simple 1:1 mapping of physical memory with the
    /// KERNEL_OFFSET added to it.
    ///
    /// For alignment the following should hold (I don't quite get
    /// what this parameter is useful for beyond the first load entry):
    /// base ≡ offset, modulo align_to. (Or rather, base % align = offset % align_to)
    fn allocate(&mut self, load_headers: elfloader::LoadableHeaders) -> Result<(), ElfLoaderErr> {
        // Should contain what memory range we need to cover to contain
        // loadable regions:
        let mut min_base: VAddr = VAddr::from(usize::MAX);
        let mut max_end: VAddr = VAddr::from(0usize);
        let mut max_alignment: u64 = 0;

        for header in load_headers.into_iter() {
            let base = header.virtual_addr();
            let size = header.mem_size() as usize;
            let align_to = header.align();
            let flags = header.flags();

            // Calculate the offset and align to page boundaries
            // We can't expect to get something that is page-aligned from ELF
            let page_base: VAddr = VAddr::from(base & !0xfff); // Round down to nearest page-size
            let size_page = round_up!(size + (base & 0xfff) as usize, BASE_PAGE_SIZE as usize);
            assert!(size_page >= size);
            assert_eq!(size_page % BASE_PAGE_SIZE, 0);
            assert_eq!(page_base % BASE_PAGE_SIZE, 0);

            // Update virtual range for ELF file [max, min] and alignment:
            if max_alignment < align_to {
                max_alignment = align_to;
            }
            if min_base > page_base {
                min_base = page_base;
            }
            if page_base + size_page as u64 > max_end {
                max_end = page_base + size_page as u64;
            }

            debug!(
                "ELF Allocate: {:#x} -- {:#x} align to {:#x}",
                page_base,
                page_base + size_page,
                align_to
            );

            #[cfg(feature = "all-writable")]
            let map_action = match (flags.is_execute(), flags.is_write(), flags.is_read()) {
                (false, false, false) => MapAction::None,
                (true, false, false) => MapAction::None,
                (false, true, false) => MapAction::None,
                (false, false, true) => MapAction::ReadKernel,
                (true, false, true) => MapAction::ReadExecuteKernel,
                (true, true, false) => MapAction::None,
                (false, true, true) => MapAction::ReadWriteKernel,
                (true, true, true) => MapAction::ReadWriteExecuteKernel,
            };

            #[cfg(not(feature = "all-writable"))]
            let map_action = match (flags.is_execute(), flags.is_write(), flags.is_read()) {
                (false, false, false) => MapAction::None,
                (true, false, false) => MapAction::None,
                (false, true, false) => MapAction::None,
                (false, false, true) => MapAction::ReadWriteKernel,
                (true, false, true) => MapAction::ReadWriteExecuteKernel,
                (true, true, false) => MapAction::None,
                (false, true, true) => MapAction::ReadWriteKernel,
                (true, true, true) => MapAction::ReadWriteExecuteKernel,
            };

            // We don't allocate yet -- just record the allocation parameters
            // This has the advantage that we know how much memory we need
            // and can reserve one consecutive chunk of physical memory
            self.mapping
                .push((page_base, size_page, align_to, map_action));
        }
        assert!(
            is_page_aligned!(min_base),
            "min base is not aligned to page-size"
        );
        assert!(
            is_page_aligned!(max_end),
            "max end is not aligned to page-size"
        );
        let pbase = VSpace::allocate_pages_aligned(
            ((max_end - min_base) >> BASE_PAGE_SHIFT) as usize,
            uefi::table::boot::MemoryType(KERNEL_ELF),
            max_alignment,
        );

        self.offset = VAddr::from(KERNEL_OFFSET + pbase.as_usize());
        info!("Kernel loaded at address: {:#x}", self.offset);

        // Do the mappings:
        for (base, size, _alignment, action) in self.mapping.iter() {
            self.vspace
                .map_generic(self.offset + *base, (pbase + base.as_u64(), *size), *action);
        }

        Ok(())
    }

    /// Load a region of bytes into the virtual address space of the process.
    fn load(
        &mut self,
        _flags: elfloader::Flags,
        destination: u64,
        region: &[u8],
    ) -> Result<(), ElfLoaderErr> {
        let destination = self.offset + destination;
        debug!(
            "ELF Load at {:#x} -- {:#x}",
            destination,
            destination + region.len()
        );

        // Load the region at destination in the kernel space
        for (idx, val) in region.iter().enumerate() {
            let vaddr = VAddr::from(destination + idx);
            let paddr = self.vspace.resolve_addr(vaddr);
            if paddr.is_some() {
                // Inefficient byte-wise copy since we don't necessarily
                // have consecutive "physical" memory in UEFI we can
                // just memcopy this stuff into.
                // Best way would probably mean to map replicate the kernel mappings
                // in UEFI space if this ever becomes a problem.
                let ptr = paddr.unwrap().as_u64() as *mut u8;
                unsafe {
                    *ptr = *val;
                }
            } else {
                panic!("Can't write to the resolved address in the kernel vspace.");
            }
        }

        Ok(())
    }

    /// Relocating the kernel symbols.
    ///
    /// Since the kernel is a position independent executable that is 'statically' linked
    /// with all dependencies we only expect to get relocations of type RELATIVE.
    /// Otherwise, the build would be broken or you got a garbage ELF file.
    /// We return an error in this case.
    fn relocate(&mut self, entry: &elfloader::Rela<elfloader::P64>) -> Result<(), ElfLoaderErr> {
        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        // The forumla for this is our offset where the kernel is starting,
        // plus the offset of the entry to jump to the code piece
        let addr = self.offset.as_u64() + entry.get_offset();

        // We can't access addr in UEFI space so we resolve it to a physical address (UEFI has 1:1 mappings)
        let uefi_addr = self
            .vspace
            .resolve_addr(VAddr::from(addr))
            .expect("Can't resolve address")
            .as_u64() as *mut u64;

        use elfloader::TypeRela64;
        if let TypeRela64::R_RELATIVE = TypeRela64::from(entry.get_type()) {
            // This is a relative relocation of a 64 bit value, we add the offset (where we put our
            // binary in the vspace) to the addend and we're done:
            unsafe {
                // Scary unsafe changing stuff in random memory locations based on
                // ELF binary values weee!
                *uefi_addr = self.offset.as_u64() + entry.get_addend();
            }
            Ok(())
        } else {
            Err(ElfLoaderErr::UnsupportedRelocationEntry)
        }
    }

    fn make_readonly(&mut self, base: u64, size: usize) -> Result<(), ElfLoaderErr> {
        trace!(
            "Make readonly {:#x} -- {:#x}",
            self.offset + base,
            self.offset + base + size
        );
        assert_eq!(
            (self.offset + base + size) % BASE_PAGE_SIZE,
            0,
            "RELRO segment doesn't end on a page-boundary"
        );

        let _from: VAddr = self.offset + (base & !0xfff); // Round down to nearest page-size
        let _to = self.offset + base + size;

        // TODO: NYI
        // self.vspace.change_rights(from, to, MapAction::ReadKernel);

        Ok(())
    }

    fn tls(
        &mut self,
        tls_data: u64,
        tls_data_len: u64,
        tls_len_total: u64,
        alignment: u64,
    ) -> Result<(), ElfLoaderErr> {
        let tls_end = tls_data + tls_len_total;
        trace!(
            "Initial TLS region is at = {:#x} -- {:#x} tls_data_len={:#x} tls_len_total={:#x} alignment={:#x}",
            tls_data, tls_end, tls_data_len, tls_len_total, alignment
        );

        self.tls = Some(TlsInfo {
            tls_data: self.offset.as_u64() + tls_data,
            tls_data_len,
            tls_len_total,
            alignment,
        });

        Ok(())
    }
}
