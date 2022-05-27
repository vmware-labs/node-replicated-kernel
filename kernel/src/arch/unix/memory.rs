// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::mem::transmute;

use log::error;
pub use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE, CACHE_LINE_SIZE, LARGE_PAGE_SIZE};

use crate::memory::Frame;

/// Maximum amount of addressable physical memory in kernel (32 TiB).
pub(crate) const KERNEL_BASE: u64 = 0x0;

/// Translate a kernel 'virtual' address to the physical address of the memory.
pub(crate) fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    let vaddr_val: usize = v.into();
    PAddr::from(vaddr_val as u64 - KERNEL_BASE)
}

/// Translate a physical memory address into a kernel addressable location.
pub(crate) fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    let paddr_val: u64 = p.into();
    VAddr::from((paddr_val + KERNEL_BASE) as usize)
}

/// Page allocator based on mmap/munmap system calls for backing slab memory.
#[derive(Default)]
pub(crate) struct MemoryMapper {
    /// Currently allocated bytes.
    currently_allocated: usize,
}

impl MemoryMapper {
    pub(crate) fn currently_allocated(&self) -> usize {
        self.currently_allocated
    }

    /// Allocates a new Frame from the system.
    ///
    /// Uses `mmap` to map.
    pub(crate) fn allocate_frame(&mut self, size: usize) -> Option<Frame> {
        if size % BASE_PAGE_SIZE != 0 {
            return None;
        }
        let mut addr: *mut libc::c_void = core::ptr::null_mut();

        let alignment = match size {
            BASE_PAGE_SIZE => BASE_PAGE_SIZE,
            _ => LARGE_PAGE_SIZE,
        };

        let r =
            unsafe { libc::posix_memalign(&mut addr as *mut *mut libc::c_void, alignment, size) };

        if r == 0 {
            let addr_ptr = addr as *const _ as *const u64;
            assert_eq!(addr_ptr as u64 % alignment as u64, 0);
            let frame = Frame::new(PAddr::from(addr_ptr as u64), size, 0);

            self.currently_allocated += size;
            Some(frame)
        } else {
            error!("Got posix memalign return {:?}", r);
            None
        }
    }

    /// Release a Frame back to the system.
    ///
    /// Uses `munmap` to release the page back to the OS.
    #[allow(unused)]
    fn release_frame(&mut self, p: Frame) {
        let addr: *mut libc::c_void = unsafe { transmute(p.base) };
        let len: libc::size_t = p.size;
        unsafe { libc::free(addr) };

        self.currently_allocated -= p.size;
    }
}
