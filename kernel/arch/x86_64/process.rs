use super::memory::{PAddr, VAddr};
use elfloader::{ElfLoader};
use elfloader::elf;

pub struct Process {
    pub pid: u64
}

impl ElfLoader for Process {
    fn allocate(&self, base: VAddr, size: usize, flags: elf::ProgFlag) {
        log!("allocate: {} {} {}", base, size, flags);
    }

    fn load(&self, destination: VAddr, region: &'static [u8]) {
        log!("load: {}", destination);
    }
}