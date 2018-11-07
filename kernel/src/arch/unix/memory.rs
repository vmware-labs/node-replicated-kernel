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
