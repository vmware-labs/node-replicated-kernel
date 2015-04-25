pub use x86::paging::{PAddr, VAddr, BASE_PAGE_SIZE};

/// Maximum amount of addressable physical memory in kernel (32 TiB).
const X86_64_PADDR_SPACE_LIMIT: u64 = 2 << 45;