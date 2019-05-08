/// Arguments that are passed on to the kernel by the bootloader.
///
/// This file is imported using include!() from the kernel source
/// so we have to be careful with imports.
#[derive(Debug)]
pub struct KernelArgs {
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
}
