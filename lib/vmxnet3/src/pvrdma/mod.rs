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
use core::pin::Pin;

use custom_error::custom_error;
use log::{debug, info};

use crate::{
    pci::BarIO,
    pvrdma::{dev_api::PVRDMA_VERSION, pvrdma::pvrdma_uar_map},
};
use pci::BarAccess;

use self::dev_api::*;

custom_error! {pub PVRDMAError
    DeviceNotSupported = "Unknown  device/version",
    InterruptModeNotSupported = "Device requested an interrupt mode that is not supported by driver",
    OutOfMemory  = "Unable to allocate raw memory.",
}

impl From<core::alloc::AllocError> for PVRDMAError {
    fn from(_e: core::alloc::AllocError) -> Self {
        PVRDMAError::OutOfMemory
    }
}

pub struct PVRDMA {
    pci: BarAccess,

    dsr_version: u32,

    /// Shared region between driver and host
    dsr: Pin<Box<pvrdma_device_shared_region>>,

    /// Is link active?
    link_active: bool,

    /// Per-device UAR (User Access Region)
    driver_uar: pvrdma_uar_map,
}

impl PVRDMA {
    pub fn new(nrx: usize, trx: usize) -> Result<Pin<Box<Self>>, PVRDMAError> {
        // TODO: supply `BarAccess` as arguments/type by kernel init
        const BUS: u32 = 0x0;
        const DEV: u32 = 0x10;
        const FUN: u32 = 0x1;
        let pci = BarAccess::new(BUS, DEV, FUN);

        let dsr_version = pci.read_bar1(PVRDMA_REG_VERSION);
        assert!(dsr_version >= PVRDMA_ROCEV1_VERSION, "Minimum version");

        info!(
            "device version {}, driver version {}",
            dsr_version, PVRDMA_VERSION
        );

        // Setup per-device UAR (User Access Region)
        let uar_start = pci.bar2;
        let driver_uar = pvrdma_uar_map::new(uar_start);
        debug_assert!(
            driver_uar.pfn <= u32::MAX as u64,
            "Supposed to be 32bit for QEMU nic (check sources)"
        );

        // Construct initial driver shared region
        let dsr = Pin::new(Box::try_new(pvrdma_device_shared_region {
            driver_version: PVRDMA_VERSION,
            gos_info: pvrdma_gos_info::new(
                pvrdma_gos_bits::PVRDMA_GOS_BITS_64,
                // Boldly tell the device we're Linux -- how can we know if
                // there isn't a perf penalty otherwise (a great example how
                // these constants are a "terrible" design choice...)
                pvrdma_gos_type::PVRDMA_GOS_TYPE_LINUX,
                1,
                0,
            ),
            uar_pfn: driver_uar.pfn,
            ..Default::default()
        })?);

        // Command slot

        // Response slot

        // Async event ring

        // CQ notification ring

        // Write the PA of the shared region to the device. The writes must be
        // ordered such that the high bits are written last. When the writes
        // complete, the device will have filled out the capabilities.

        let drv = Box::try_new(Self {
            pci,
            dsr_version,
            dsr,
            driver_uar,
            link_active: false,
        })?;

        Ok(Pin::new(drv))
    }

    pub fn register(&self) {}

    pub fn msix_intr_assign(&self) {}
    pub fn free_irqs(&self) {}
    pub fn detach(&self) {}
    pub fn shutdown(&self) {}
    pub fn suspend(&self) {}
    pub fn resume(&self) {}

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
