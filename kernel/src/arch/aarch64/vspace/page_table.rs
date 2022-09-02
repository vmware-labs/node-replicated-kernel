// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::pin::Pin;

use crate::memory::vspace::*;
use crate::memory::{PAddr, VAddr};
use armv8::aarch64::vm::granule4k::L0Table; // Frame, kernel_vaddr_to_paddr, paddr_to_kernel_vaddr,

use crate::error::KError;

pub(crate) struct PageTable {
    pub pml4: Pin<Box<L0Table>>,
    //pub da: Option<DA>,
}

impl PageTable {
    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        insert_mapping: bool,
    ) -> Result<(), KError> {
        panic!("not yet implemented!");
    }
}
