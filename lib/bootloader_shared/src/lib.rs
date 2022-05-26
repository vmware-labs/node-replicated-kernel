// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of data-structures that are shared between the booatloader
//! and the kernel (i.e., they are passed by the bootloader
//! to the kernel).
//!
//! # Warnings
//! This is a bit shady since we pass these structs as in-memory blobs
//! between the kernel and bootloader (both of which have different
//! architectural targets). In a best-case scenario this
//! just works, but it's best if these structs stay plain-old-data
//! without any implementations etc.
#![no_std]
#![feature(const_mut_refs)]
extern crate alloc;

use alloc::vec::Vec;

/// Describes an ELF binary we loaded from the UEFI image into memory.
#[derive(Eq, PartialEq, Clone)]
pub struct Module {
    /// Name of the module (ELF file).
    pub name: [u8; Module::MAX_NAME_LEN],
    /// Length of name
    pub name_len: usize,
    /// Where in memory the binary is (kernel virtual address).
    pub binary_vaddr: x86::bits64::paging::VAddr,
    /// Where in memory the binary is (physical address)
    pub binary_paddr: x86::bits64::paging::PAddr,
    /// How big the binary is (in bytes)
    pub binary_size: usize,
}

impl Module {
    /// Maximum supported name for a module
    pub const MAX_NAME_LEN: usize = 32;

    /// Create a new module to pass to the kernel.
    /// The name will be truncated to 32 bytes.
    pub fn new(
        name: &str,
        binary_vaddr: x86::bits64::paging::VAddr,
        binary_paddr: x86::bits64::paging::PAddr,
        binary_size: usize,
    ) -> Module {
        let mut name_slice: [u8; Module::MAX_NAME_LEN] = [0; Module::MAX_NAME_LEN];
        let len = core::cmp::min(name.len(), Module::MAX_NAME_LEN);
        name_slice[0..len].copy_from_slice(&name.as_bytes()[0..len]);

        Module {
            name: name_slice,
            name_len: len,
            binary_vaddr,
            binary_paddr,
            binary_size,
        }
    }

    /// Return the name of the module (or at least the first 32 bytes).
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[0..self.name_len]).unwrap_or("unknown")
    }

    /// Base address of the binary blob (in kernel space).
    #[allow(unused)]
    pub fn base(&self) -> x86::bits64::paging::VAddr {
        self.binary_vaddr
    }

    /// Size of the binary blob.
    #[allow(unused)]
    pub fn size(&self) -> usize {
        self.binary_size
    }

    /// Return a slice to the binary loaded in the (kernel) address space.
    ///
    /// # Safety
    /// May not be mapped at all (for example in UEFI bootloader space).
    /// May be unmapped/changed arbitrarily later by the kernel.
    #[allow(unused)]
    pub unsafe fn as_slice(&self) -> &'static [u8] {
        core::slice::from_raw_parts(self.base().as_ptr::<u8>(), self.size())
    }

    /// Return a slice to the binary loaded in the physical address space.
    ///
    /// # Safety
    /// May not be mapped at all (for example in kernel space).
    /// May be unmapped/changed arbitrarily later by the kernel.
    #[allow(unused)]
    pub unsafe fn as_pslice(&self) -> &'static [u8] {
        core::slice::from_raw_parts(self.binary_paddr.0 as *const u8, self.size())
    }
}

impl core::fmt::Debug for Module {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut w = f.debug_struct("Module");
        w.field("name", &self.name());
        w.field(
            "binary",
            &format_args!("({:#x}, {:#x})", self.binary_vaddr, self.binary_size),
        );
        w.finish()
    }
}

/// Information about the TLS region of the kernel binary.
#[repr(C)]
#[derive(Debug)]
pub struct TlsInfo {
    pub tls_data: u64,
    pub tls_data_len: u64,
    pub tls_len_total: u64,
    pub alignment: u64,
}

/// Arguments that are passed on to the kernel by the bootloader.
#[repr(C)]
#[derive(Debug)]
pub struct KernelArgs {
    /// Physical base address and size of the UEFI memory map (constructed on boot services exit).
    pub mm: (x86::bits64::paging::PAddr, usize),

    /// Iterator over memory map
    pub mm_iter: Vec<uefi::table::boot::MemoryDescriptor>,

    /// String of the command line
    pub command_line: &'static str,

    /// A slice into the GPU frame-buffer
    pub frame_buffer: Option<&'static mut [u8]>,

    /// Current video mode that was set by the boot-loader
    pub mode_info: Option<uefi::proto::console::gop::ModeInfo>,

    /// The physical base address of root PML4 (page) for the kernel
    /// address space that gets loaded in cr3.
    /// The kernel can also find this by reading cr3.
    pub pml4: x86::bits64::paging::PAddr,

    /// Kernel stack base address and stack size.
    pub stack: (x86::bits64::paging::PAddr, usize),

    /// The offset where the elfloader placed the kernel
    pub kernel_elf_offset: x86::bits64::paging::VAddr,

    /// The physical address of the ACPIv1 RSDP (Root System Description Pointer)
    pub acpi1_rsdp: x86::bits64::paging::PAddr,

    /// The physical address of the ACPIv2 RSDP (Root System Description Pointer)
    pub acpi2_rsdp: x86::bits64::paging::PAddr,

    /// Information from the TLS section of the kernel ELF
    /// (if it exists)
    pub tls_info: Option<TlsInfo>,

    /// Modules (ELF binaries found in the UEFI partition) passed to the kernel
    /// modules[0] is the kernel binary
    pub modules: arrayvec::ArrayVec<Module, { KernelArgs::MAX_MODULES }>,
}

impl KernelArgs {
    pub const fn new() -> Self {
        Self {
            mm: (x86::bits64::paging::PAddr(0), 0),
            mm_iter: Vec::new(),
            command_line: "<< unset >>",
            frame_buffer: None,
            mode_info: None,
            pml4: x86::bits64::paging::PAddr(0),
            stack: (x86::bits64::paging::PAddr(0), 0),
            kernel_elf_offset: x86::bits64::paging::VAddr(0),
            acpi1_rsdp: x86::bits64::paging::PAddr(0),
            acpi2_rsdp: x86::bits64::paging::PAddr(0),
            tls_info: None,
            modules: arrayvec::ArrayVec::new_const(),
        }
    }

    /// Get a slice to the kernel ELF binary.
    ///
    /// The binary is useful for symbol name lookups when printing backtraces in
    /// case things go wrong (see panic.rs).
    ///
    /// # Safety
    /// - The kernel binary / module[0] must be mapped in the kernel address
    ///   space at the same address as we passed along in the bootloader.
    /// - There must be at least one module present (this is guaranteed when
    ///   using the struct that's passed to the kernel by the bootloader but not
    ///   for arbitrary new KernelArgs)
    #[allow(unused)]
    pub unsafe fn kernel_binary(&self) -> &'static [u8] {
        use core::slice;
        slice::from_raw_parts(
            self.modules[0].base().as_u64() as *const u8,
            self.modules[0].size(),
        )
    }
}

impl Default for KernelArgs {
    fn default() -> Self {
        KernelArgs::new()
    }
}

impl KernelArgs {
    pub const MAX_MODULES: usize = 32;
}
