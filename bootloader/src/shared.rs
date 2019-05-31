// A set of data-structures that are shared between the booatloader
// and the kernel (i.e., they are passed by the bootloader
// to the kernel).
//
// # Notes
// This file is imported using include!() from the kernel source
// so we have to be careful with imports (use full qualifiers).
// That's also the reason why this isn't a rustdoc comment.

/// Describes an ELF binary we loaded from the UEFI image into memory.
#[derive(Clone)]
pub struct Module {
    /// Name of the module (ELF file).
    pub name: [u8; 32],
    /// Length of name
    pub name_len: usize,
    /// Where in memory the binary is and how big it is (in bytes).
    pub binary: (x86::bits64::paging::VAddr, usize),
}

impl Module {
    /// Create a new module to pass to the kernel.
    /// The name will be truncated to 32 bytes.
    pub(crate) fn new(name: &str, binary: (x86::bits64::paging::VAddr, usize)) -> Module {
        let mut name_slice: [u8; 32] = [0; 32];
        let len = core::cmp::min(name.len(), 32);
        name_slice[0..len].copy_from_slice(&name.as_bytes()[0..len]);

        Module {
            name: name_slice,
            name_len: len,
            binary: binary,
        }
    }

    /// Return the name of the module (or at least the first 32 bytes).
    pub(crate) fn name(&self) -> &str {
        core::str::from_utf8(&self.name[0..self.name_len]).unwrap_or("unknown")
    }

    /// Base physical address of the binary blob.
    pub(crate) fn base(&self) -> x86::bits64::paging::VAddr {
        self.binary.0
    }

    /// Size of the binary blob.
    pub(crate) fn size(&self) -> usize {
        self.binary.1
    }

    /// Return a slice to the binary loaded in the (kernel) address space.
    ///
    /// # Unsafe
    /// May not be mapped at all (for example in UEFI bootloader space).
    /// May be unmapped/changed arbitrarily later by the kernel.
    pub(crate) unsafe fn as_slice(&self) -> &'static [u8] {
        core::slice::from_raw_parts(self.base().as_ptr::<u8>(), self.size())
    }
}

impl core::fmt::Debug for Module {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut w = f.debug_struct("Module");
        w.field("name", &self.name());
        w.field(
            "binary",
            &format_args!("({:#x}, {:#x})", self.binary.0, self.binary.1),
        );
        w.finish()
    }
}

/// Arguments that are passed on to the kernel by the bootloader.
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
    /// The offset where the elfloader placed the kernel
    pub kernel_elf_offset: x86::bits64::paging::VAddr,
    /// The physical address of the ACPIv1 RSDP (Root System Description Pointer)
    pub acpi1_rsdp: x86::bits64::paging::PAddr,
    /// The physical address of the ACPIv2 RSDP (Root System Description Pointer)
    pub acpi2_rsdp: x86::bits64::paging::PAddr,
    /// Modules (ELF binaries found in the UEFI partition) passed to the kernel
    /// modules[0] is the kernel binary
    pub modules: T,
}
