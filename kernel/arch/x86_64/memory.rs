/// Physical address type in system
pub type PAddr = u64;

/// Virtual address type in system
pub type VAddr = u64;

/// Size of physical address space
pub const PADDR_SPACE_BITS: u64 = 48;
pub const PADDR_SPACE_SIZE: u64 = 1 << PADDR_SPACE_BITS;

/// Virtual base page size
pub const BASE_PAGE_BITS: u64 = 12;
pub const BASE_PAGE_SIZE: u64 = 1 << BASE_PAGE_BITS;

