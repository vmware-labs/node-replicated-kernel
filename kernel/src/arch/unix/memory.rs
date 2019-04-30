use core::mem::{transmute, uninitialized};
use core::ptr;

use crate::memory::Frame;
pub use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE, CACHE_LINE_SIZE};

/// Maximum amount of addressable physical memory in kernel (32 TiB).
//const X86_64_PADDR_SPACE_LIMIT: u64 = 2 << 45;
const KERNEL_BASE: u64 = 0x0;

/// Translate a kernel 'virtual' address to the physical address of the memory.
pub fn kernel_vaddr_to_paddr(v: VAddr) -> PAddr {
    let vaddr_val: usize = v.into();
    PAddr::from(vaddr_val as u64 - KERNEL_BASE)
}

/// Translate a physical memory address into a kernel addressable location.
pub fn paddr_to_kernel_vaddr(p: PAddr) -> VAddr {
    let paddr_val: u64 = p.into();
    VAddr::from((paddr_val + KERNEL_BASE) as usize)
}

/// Page allocator based on mmap/munmap system calls for backing slab memory.
pub struct MemoryMapper {
    /// Currently allocated bytes.
    currently_allocated: usize,
}

impl MemoryMapper {
    pub fn new() -> MemoryMapper {
        MemoryMapper {
            currently_allocated: 0,
        }
    }
}

impl MemoryMapper {
    pub fn currently_allocated(&self) -> usize {
        self.currently_allocated
    }

    /// Allocates a new Frame from the system.
    ///
    /// Uses `mmap` to map.
    pub(crate) fn allocate_frame(&mut self, size: usize) -> Option<Frame> {
        let mut addr: libc::c_void = unsafe { uninitialized() };
        let len: libc::size_t = size as libc::size_t;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON;
        let fd = -1;
        let offset = 0;

        let r = unsafe { libc::mmap(&mut addr, len as libc::size_t, prot, flags, fd, offset) };
        if r == libc::MAP_FAILED {
            return None;
        } else {
            let frame = Frame::new(PAddr::from(r as u64), size);
            self.currently_allocated += size;
            return Some(frame);
        }
    }

    /// Release a Frame back to the system.
    ///
    /// Uses `munmap` to release the page back to the OS.
    fn release_frame(&mut self, p: Frame) {
        let addr: *mut libc::c_void = unsafe { transmute(p.base) };
        let len: libc::size_t = p.size;
        let r = unsafe { libc::munmap(addr, len) };
        if r != 0 {
            panic!("munmap failed!");
        }

        self.currently_allocated -= p.size;
    }
}
