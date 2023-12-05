use core::slice::from_raw_parts_mut;
use x86::bits64::paging::LARGE_PAGE_SIZE;

use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};
use log::info;

pub const BASE: u64 = 0x0510_0000_0000;
pub const MAX_FRAMES: u64 = 600;

#[derive(Clone, Copy)]
pub struct MyAllocator;

impl Default for MyAllocator {
    fn default() -> Self {
        let mut allocated = 0;
        while allocated < MAX_FRAMES {
            // Allocate a large page of physical memory
            // Note that even if you allocate a base page, behind the scenes a large page is allocated
            // because DCM (and thus DiNOS) only allocates at large page granularity
            // 1 is the client machine id we want to allocate from
            let (frame_id, paddr) = vibrio::syscalls::PhysicalMemory::allocate_large_page(1)
                .expect("Failed to get physical memory large page");
            info!("large frame id={:?}, paddr={:?}", frame_id, paddr);

            // Map allocated physical memory into user space so we can actually access it.
            unsafe {
                vibrio::syscalls::VSpace::map_frame(
                    frame_id,
                    BASE + (allocated * LARGE_PAGE_SIZE as u64),
                )
                .expect("Failed to map base page");
            }
            allocated += 1;
        }
        info!("# Allocated {} frames", allocated);
        MyAllocator {}
    }
}

unsafe impl Allocator for MyAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        info!("# Allocating {:?}", layout);
        if layout.size() > LARGE_PAGE_SIZE * MAX_FRAMES as usize {
            return Err(AllocError);
        }

        let slice = unsafe { from_raw_parts_mut(BASE as *mut u8, layout.size()) };
        // DO we need to zero the memory for mapping to work?
        Ok(NonNull::from(slice))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        info!("# Deallocating {:?}", layout);
        vibrio::syscalls::VSpace::unmap(ptr.as_ptr() as u64, layout.size() as u64)
            .expect("Failed to unmap base page");
    }
}
