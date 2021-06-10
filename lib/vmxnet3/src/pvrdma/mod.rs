// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! This module contains the PVRDMA device driver, a virtual RDMA driver that is
//! an extension of vmxnet3. It is supported by ESX and QEMU/Linux. A reference
//! implementation exists in the Linux kernel that is licensed as BSD-2-Clause
//! and GPL2.
//!
//! # Online Documentation / Sources
//! - https://github.com/qemu/qemu/blob/master/docs/pvrdma.txt
//! - https://blog.linuxplumbersconf.org/2017/ocw/system/presentations/4730/original/lpc-2017-pvrdma-marcel-apfelbaum-yuval-shaia.pdf
//! - https://elixir.bootlin.com/linux/latest/source/drivers/infiniband/hw/vmw_pvrdma

mod pci;

mod dev_api;
mod pvrdma;
mod verbs;

use alloc::boxed::Box;

use custom_error::custom_error;
use log::debug;

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
        // TODO: supply as arguments/type
        const BUS: u32 = 0x0;
        const DEV: u32 = 0x10;
        const FUN: u32 = 0x1;

        let pci = BarAccess::new(BUS, DEV, FUN);

        Err(PVRDMAError::OutOfMemory)
    }

    fn pci_probe(&mut self) {
        debug!("Initializing pvrdma driver");
    }

    fn init_device(&mut self) {}
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
