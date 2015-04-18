use prelude::*;

use super::memory::{PAddr, VAddr};
use ::mm::{FrameManager};

use elfloader::{ElfLoader};
use elfloader::elf;
use x86::mem::{PML4, PML4Entry, BASE_PAGE_SIZE};

//use std::option;

macro_rules! round_up {
   ( $num:expr, $s:expr ) => { (($num + $s - 1) / $s) * $s }
}

pub struct VSpace<'a> {
    pub pml4: &'a mut PML4,
}

impl<'a> VSpace<'a> {
    pub fn map(&mut self, base: VAddr, size: usize) {
        for e in self.pml4.iter() {
            log!("PML4 {:?}", e);
        }
    }
}

pub struct Process<'a> {
    pub pid: u64,
    fm: &'a mut FrameManager,
    pub vspace: VSpace<'a>,
}

impl<'a> Process<'a> {
    pub fn new<'b>(fm: &'b mut FrameManager) -> Option<Process> {
        let pml4 = fm.allocate_pml4();
        match pml4 {

            Some(table) => {
                Some(Process{pid: 0, fm: fm, vspace: VSpace{pml4: table} })
            }
            None => None
        }
    }
}

impl<'a> ElfLoader for Process<'a> {
    fn allocate(&mut self, base: VAddr, size: usize, flags: elf::ProgFlag) {
        let rsize = round_up!(size, BASE_PAGE_SIZE as usize);
        let frame = self.fm.allocate_frame(rsize as u64);

        match frame {
            Some(f) => log!("frame = {:?}", f),
            None => log!("Not enough mem")
        };

        self.vspace.map(base, size);
    }

    fn load(&mut self, destination: VAddr, region: &'static [u8]) {
        log!("load: {}", destination);
    }
}