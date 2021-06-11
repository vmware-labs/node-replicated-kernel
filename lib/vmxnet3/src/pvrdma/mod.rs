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
use core::{alloc::Layout, pin::Pin};
use driverkit::iomem::DmaObject;
use x86::current::paging::{IOAddr, PAddr, VAddr, BASE_PAGE_SIZE};

use custom_error::custom_error;
use log::{debug, info};
use static_assertions as sa;

use crate::{
    pci::BarIO,
    pvrdma::{dev_api::PVRDMA_VERSION, pvrdma::pvrdma_uar_map},
};
use pci::BarAccess;

use self::{dev_api::*, pci::KERNEL_BASE};

const PAGE_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE) };
// Safety constraints for PAGE_LAYOUT:
sa::const_assert!(BASE_PAGE_SIZE > 0); // align must not be zero
sa::const_assert!(BASE_PAGE_SIZE.is_power_of_two()); // align must be a power of two

pub struct DmaBuffer<const LEN: usize> {
    buf: *mut u8,
}

impl<const LEN: usize> DmaBuffer<LEN> {
    fn new() -> Result<Self, PVRDMAError> {
        let buf = unsafe { alloc::alloc::alloc(PAGE_LAYOUT) };
        if buf.is_null() {
            return Err(PVRDMAError::OutOfMemory);
        }

        Ok(Self { buf })
    }
}

impl<const LEN: usize> Drop for DmaBuffer<LEN> {
    fn drop(&mut self) {
        unsafe {
            debug_assert!(!self.buf.is_null());
            let layout = Layout::from_size_align_unchecked(LEN, BASE_PAGE_SIZE);
            alloc::alloc::dealloc(self.buf, layout);
        }
    }
}

impl<const LEN: usize> DmaObject for DmaBuffer<LEN> {
    fn paddr(&self) -> PAddr {
        PAddr::from(self.buf as *const () as u64) - PAddr::from(KERNEL_BASE)
    }

    fn vaddr(&self) -> VAddr {
        VAddr::from(self.buf as *const Self as *const () as usize)
    }

    fn ioaddr(&self) -> IOAddr {
        IOAddr::from(self.paddr().as_u64())
    }
}

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

    cmd_slot: DmaBuffer<BASE_PAGE_SIZE>,
    resp_slot: DmaBuffer<BASE_PAGE_SIZE>,

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
            dsr_version >= PVRDMA_PPN64_VERSION || driver_uar.pfn <= u32::MAX as u64,
            "Must be <32bit for the QEMU NIC device (check source)"
        );

        // Command & Response slot
        let cmd_slot = DmaBuffer::<BASE_PAGE_SIZE>::new()?;
        let resp_slot = DmaBuffer::<BASE_PAGE_SIZE>::new()?;

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
            cmd_slot_dma: cmd_slot.ioaddr().as_u64(),
            resp_slot_dma: resp_slot.ioaddr().as_u64(),
            ..Default::default()
        })?);

        // Async event ring

        // CQ notification ring

        // Write the PA of the shared region to the device. The writes must be
        // ordered such that the high bits are written last. When the writes
        // complete, the device will have filled out the capabilities.

        let drv = Box::try_new(Self {
            pci,
            cmd_slot,
            resp_slot,
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
