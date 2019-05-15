/// Describes an ELF binary we loaded from the UEFI image into memory.
#[derive(Debug)]
pub struct Module {
    /// Name of the module (ELF file).
    pub name: [u8; 32],
    /// Where in memory the binary is and how big it is (in bytes).
    pub binary: (x86::bits64::paging::PAddr, usize),
}

/// Arguments that are passed on to the kernel by the bootloader.
///
/// This file is imported using include!() from the kernel source
/// so we have to be careful with imports.
#[derive(Debug)]
pub struct KernelArgs<T: ?Sized> {
    /// Physical base address and size of the UEFI memory map (constructed on boot services exit).
    pub mm: (x86::bits64::paging::PAddr, usize),
    /// Iterator over memory map
    pub mm_iter: uefi::table::boot::MemoryMapIter<'static>,
    /// The physical base address of root PML4 (page) for the kernel
    /// address space that gets loaded in cr3.
    /// The kernel can also find this by reading cr3.
    pub pml4: x86::bits64::paging::PAddr,
    /// Kernel stack base address and stack size.
    pub stack: (x86::bits64::paging::PAddr, usize),
    /// Mapping location of the loaded kernel binary file and it's size.
    pub kernel_binary: (x86::bits64::paging::PAddr, usize),
    /// The offset where the elfloader placed the kernel
    pub kernel_elf_offset: x86::bits64::paging::VAddr,
    /// The physical address of the ACPIv1 RSDP (Root System Description Pointer)
    pub acpi1_rsdp: x86::bits64::paging::PAddr,
    /// The physical address of the ACPIv2 RSDP (Root System Description Pointer)
    pub acpi2_rsdp: x86::bits64::paging::PAddr,
    /// Modules (ELF binaries we load as user-space program) passed to the kernel
    pub modules: T,
}
