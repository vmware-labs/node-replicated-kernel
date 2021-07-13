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
mod dmabuffer;
mod pagedir;
mod pvrdma;
mod verbs;

use alloc::boxed::Box;
use core::convert::TryInto;
use core::ptr::NonNull;
use core::{alloc::Layout, pin::Pin};
use driverkit::iomem::DmaObject;
use x86::current::paging::BASE_PAGE_SIZE;

use custom_error::custom_error;
use log::{debug, info, warn};
use static_assertions as sa;

use self::dev_api::PVRDMA_VERSION;
use self::pagedir::pvrdma_page_dir;
use self::pvrdma::{pvrdma_uar_map, PVRDMA_NUM_RING_PAGES};

use crate::pci::BarIO;
use pci::BarAccess;

use self::{dev_api::*, dmabuffer::DmaBuffer};

const PAGE_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(BASE_PAGE_SIZE, BASE_PAGE_SIZE) };
// Safety constraints for PAGE_LAYOUT:
sa::const_assert!(BASE_PAGE_SIZE > 0); // align must not be zero
sa::const_assert!(BASE_PAGE_SIZE.is_power_of_two()); // align must be a power of two

custom_error! {pub PVRDMAError
    DeviceNotSupported = "Unknown  device/version",
    InterruptModeNotSupported = "Device requested an interrupt mode that is not supported by driver",
    PdirTooManyPages = "Too many pages for the pdir requested",
    PageIndexOutOfRange = "supplied index was out of range",
    InvalidMemoryReference = "No page set",
    OutOfMemory  = "Unable to allocate raw memory.",
    CommandFault = "Failed to post a command to the device",
    CommandFaultResponse = "Unknown response from device",
    TooManyEntries = "Too many entries for the queue"
}

impl From<core::alloc::AllocError> for PVRDMAError {
    fn from(_e: core::alloc::AllocError) -> Self {
        PVRDMAError::OutOfMemory
    }
}

impl From<fallible_collections::TryReserveError> for PVRDMAError {
    fn from(_e: fallible_collections::TryReserveError) -> Self {
        PVRDMAError::OutOfMemory
    }
}

pub struct PVRDMA {
    pci: BarAccess,

    dsr_version: u32,

    cmd_slot: DmaBuffer<BASE_PAGE_SIZE>,
    resp_slot: DmaBuffer<BASE_PAGE_SIZE>,

    /// Async event ring
    async_pdir: pvrdma_page_dir,

    /// Pointer to current page in `async_pdir`
    /// TODO: For rust might be better if this remains a page_idx...
    async_ring_state: NonNull<[u8]>,

    /// Completion queue notification ring
    cq_pdir: pvrdma_page_dir,

    /// Pointer to current page in `cq_pdir`
    /// TODO: For rust might be better if this remains a page_idx...
    cq_ring_state: NonNull<[u8]>,

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

        // Async event ring
        let npages = PVRDMA_NUM_RING_PAGES;
        let async_pdir = pvrdma_page_dir::new(npages.try_into().unwrap(), true)?;
        let async_ring_state = async_pdir.pages[0];
        let async_ring_pages = pvrdma_ring_page_info::new(npages, async_pdir.ioaddr());

        // CQ notification ring
        let npages = PVRDMA_NUM_RING_PAGES;
        let cq_pdir = pvrdma_page_dir::new(npages.try_into().unwrap(), true)?;
        let cq_ring_state = cq_pdir.pages[0];
        let cq_ring_pages = pvrdma_ring_page_info::new(npages, cq_pdir.ioaddr());

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
            async_ring_pages,
            cq_ring_pages,
            ..Default::default()
        })?);

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
            async_pdir,
            async_ring_state,
            cq_pdir,
            cq_ring_state,
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

    fn cmd_recv(&self, resp: &mut pvrdma_cmd_resp, resp_code: u32) -> Result<(), PVRDMAError> {
        // TODO: wait for completion

        // maybe warp the copy in a spinlock
        self.cmd_slot.copy_out(resp.as_mut_slice());

        if unsafe { resp.hdr.ack } != resp_code {
            warn!(
                "unknown response {} expected {}",
                unsafe { resp.hdr.ack },
                resp_code
            );
            return Err(PVRDMAError::CommandFaultResponse);
        }

        return Ok(());
    }

    pub fn cmd_post(
        &self,
        cmd: &pvrdma_cmd_req,
        resp: Option<(&mut pvrdma_cmd_resp, pvrdma_resp_cmd_typ)>,
    ) -> Result<(), PVRDMAError> {
        // take the lock, if needed...

        // copy in the buffer
        // 	spin_lock(&dev->cmd_lock);
        self.cmd_slot.copy_in(cmd.as_slice());
        // 	spin_unlock(&dev->cmd_lock);

        // initialize the completion, just clear the first
        // not sure how we do this on bespin...
        // init_completion(&dev->cmd_done);

        // issue a barrier to ensure the requiest is written
        // 	mb();

        // 	pvrdma_write_reg(dev, PVRDMA_REG_REQUEST, 0);
        //buswrite(self.bar1, PVRDMA_REG_REQUEST, 0)
        self.pci.write_bar1(PVRDMA_REG_REQUEST, 0);

        // issue a barrier to ensure the requiest is written
        // 	mb();
        let err = self.pci.read_bar1(PVRDMA_REG_ERR);
        if err == 0 {
            match resp {
                Some((r, c)) => return self.cmd_recv(r, c as u32),
                None => return Ok(()),
            }
        } else {
            warn!("failed to post request to pvrdma device");
            return Err(PVRDMAError::CommandFault);
        }
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
