// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! PVRDMA device for VMs
//!
//! # Additional Documentation
//! - https://github.com/qemu/qemu/blob/master/docs/pvrdma.txt
//! - https://blog.linuxplumbersconf.org/2017/ocw/system/presentations/4730/original/lpc-2017-pvrdma-marcel-apfelbaum-yuval-shaia.pdf
//!

mod defs;
mod pci;

use alloc::boxed::Box;

use custom_error::custom_error;
use pci::BarAccess;

custom_error! {pub PVRDMAError
    DeviceNotSupported = "Unknown  device/version",
    InterruptModeNotSupported = "Device requested an interrupt mode that is not supported by driver",
    OutOfMemory  = "Unable to allocate raw memory.",
}

pub struct PVRDMA {
    pci: BarAccess,

    /// Is link active?
    link_active: bool,
}

impl PVRDMA {
    pub fn new(nrx: usize, trx: usize) -> Result<Box<PVRDMA>, PVRDMAError> {
        Err(PVRDMAError::OutOfMemory)
    }
}

/*
static inline void pvrdma_write_reg(struct pvrdma_dev *dev, u32 reg, u32 val)
{
    writel(cpu_to_le32(val), dev->regs + reg);
}

static inline u32 pvrdma_read_reg(struct pvrdma_dev *dev, u32 reg)
{
    return le32_to_cpu(readl(dev->regs + reg));
}

*/
