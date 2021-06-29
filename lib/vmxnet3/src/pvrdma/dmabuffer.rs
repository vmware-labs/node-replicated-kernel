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

use core::alloc::Layout;
use core::slice;
use driverkit::iomem::DmaObject;
use x86::current::paging::{IOAddr, PAddr, VAddr, BASE_PAGE_SIZE};

use super::{pci::KERNEL_BASE, PVRDMAError};

pub struct DmaBuffer<const LEN: usize> {
    buf: *mut u8,
}

impl<const LEN: usize> DmaBuffer<LEN> {
    pub fn new() -> Result<Self, PVRDMAError> {
        let layout = Layout::from_size_align(LEN, BASE_PAGE_SIZE).unwrap();
        let buf = unsafe { alloc::alloc::alloc(layout) };
        if buf.is_null() {
            return Err(PVRDMAError::OutOfMemory);
        }

        Ok(Self { buf })
    }

    pub fn as_slice(&self) -> &[u8] {
        debug_assert!(!self.buf.is_null());
        unsafe { slice::from_raw_parts(self.buf, LEN) }
    }

    pub fn as_mut_slice(&self) -> &mut [u8] {
        debug_assert!(!self.buf.is_null());
        unsafe { slice::from_raw_parts_mut(self.buf, LEN) }
    }

    pub fn copy_in(&self, other: &[u8]) {
        let buf = self.as_mut_slice();
        buf.copy_from_slice(other);
    }

    pub fn copy_out(&self, other: &mut [u8]) {
        let buf = self.as_slice();
        other.copy_from_slice(buf);
    }

    pub fn clear_n(&self, n: usize) {
        let buf = self.as_mut_slice();
        if n > buf.len() {
            self.clear()
        } else {
            for i in &mut buf[0..n] {
                *i = 0
            }
        }
    }

    pub fn clear(&self) {
        let buf = self.as_mut_slice();
        for i in &mut buf[..] {
            *i = 0
        }
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
