use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};

use super::KernelDebugger;
use crate::error::KError;

impl SectionOffsets for KernelDebugger {
    /// Tells GDB where in memory the bootloader has put our kernel binary.
    fn get_section_offsets(&mut self) -> Result<Offsets<u64>, KError> {
        let kernel_reloc_offset = crate::KERNEL_ARGS
            .get()
            .map_or(0x0, |args| args.kernel_elf_offset.as_u64());
        Ok(Offsets::Sections {
            text: kernel_reloc_offset,
            data: kernel_reloc_offset,
            bss: None,
        })
    }
}
