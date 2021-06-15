// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! PCI Bars:
//! BAR 0 - MSI-X
//!         MSI-X vectors:
//!        (0) Command - used when execution of a command is completed.
//!        (1) Async - not in use.
//!        (2) Completion - used when a completion event is placed in
//!          device's CQ ring.
//! BAR 1 - Registers
//!         --------------------------------------------------------
//!         | VERSION |  DSR | CTL | REQ | ERR |  ICR | IMR  | MAC |
//!         --------------------------------------------------------
//!        DSR - Address of driver/device shared memory used
//!               for the command channel, used for passing:
//!                - General info such as driver version
//!                - Address of 'command' and 'response'
//!                - Address of async ring
//!                - Address of device's CQ ring
//!                - Device capabilities
//!        CTL - Device control operations (activate, reset etc)
//!        IMG - Set interrupt mask
//!        REQ - Command execution register
//!        ERR - Operation status
//!
//! BAR 2 - UAR
//!         ---------------------------------------------------------
//!         | QP_NUM  | SEND/RECV Flag ||  CQ_NUM |   ARM/POLL Flag |
//!         ---------------------------------------------------------
//!        - Offset 0 used for QP operations (send and recv)
//!        - Offset 4 used for CQ operations (arm and poll)

use crate::pci::{busread, buswrite, confread, confwrite, BarIO};

pub use crate::pci::KERNEL_BASE;
use x86::current::paging::{PAddr, VAddr};

///  TODO: get rid of this:
pub fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    let vaddr_val: usize = v.into();
    PAddr::from(vaddr_val as u64 - KERNEL_BASE)
}

///  TODO: get rid of this:
pub fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    let paddr_val: u64 = p.into();
    VAddr::from((paddr_val + KERNEL_BASE) as usize)
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct BarAccess {
    /// Bus, device, function triplet of PCI device
    pci_addr: (u32, u32, u32),
    /// MSI-X
    pub bar0: u64,
    /// Registers
    pub bar1: u64,
    /// UAR
    pub bar2: u64,
}

impl BarAccess {
    pub(crate) fn new(bus: u32, dev: u32, fun: u32) -> Self {
        unsafe {
            //let devline = confread(bus, dev, fun, 0x0);
            //assert_eq!(devline, 0x7b015ad, "Sanity check for vmxnet3");

            let bar0 = confread(bus, dev, fun, 0x10);
            let bar1 = confread(bus, dev, fun, 0x14);
            let bar2 = confread(bus, dev, fun, 0x18);
            //let bar_msix = pci::confread(BUS, DEV, FUN, 0x7);

            log::debug!("BAR0 at: {:#x}", bar0);
            log::debug!("BAR1 at: {:#x}", bar1);
            log::debug!("BAR2 at: {:#x}", bar2);
            //debug!("MSI-X at: {:#x}", bar_msi);

            BarAccess {
                pci_addr: (bus, dev, fun),
                bar0: bar0.into(),
                bar1: bar1.into(),
                bar2: bar2.into(),
            }
        }
    }
}

impl BarIO for BarAccess {
    fn read_bar0(&self, offset: u64) -> u32 {
        unsafe { busread(self.bar0, offset) }
    }

    fn write_bar0(&self, offset: u64, data: u32) {
        unsafe { buswrite(self.bar0, offset, data) };
    }

    fn read_bar1(&self, offset: u64) -> u32 {
        unsafe { busread(self.bar1, offset) }
    }

    fn write_bar1(&self, offset: u64, data: u32) {
        unsafe { buswrite(self.bar1, offset, data) };
    }
}
