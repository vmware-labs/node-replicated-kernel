use core::slice::from_raw_parts_mut;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use x86::bits64::paging::LARGE_PAGE_SIZE;

use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};
use log::info;

pub const BASE: u64 = 0x0510_0000_0000;
pub const MAX_FRAMES: u64 = 600;

static NODE_ID: AtomicU8 = AtomicU8::new(1);

#[derive(Clone, Copy)]
pub struct MyAllocator;

impl MyAllocator {
    fn allocate_pages(node_id: u8) {
        let mut allocated = 0;
        let node_offset = (node_id - 1) as u64 * LARGE_PAGE_SIZE as u64 * MAX_FRAMES;
        while allocated < MAX_FRAMES {
            // Allocate a large page of physical memory
            // Note that even if you allocate a base page, behind the scenes a large page is allocated
            // because DCM (and thus DiNOS) only allocates at large page granularity
            // 1 is the client machine id we want to allocate from
            let (frame_id, paddr) =
                vibrio::syscalls::PhysicalMemory::allocate_large_page(node_id as usize)
                    .expect("Failed to get physical memory large page");
            info!("large frame id={:?}, paddr={:?}", frame_id, paddr);

            // Map allocated physical memory into user space so we can actually access it.
            unsafe {
                vibrio::syscalls::VSpace::map_frame(
                    frame_id,
                    BASE + node_offset + (allocated * LARGE_PAGE_SIZE as u64),
                )
                .expect("Failed to map base page");
            }
            allocated += 1;
        }
        info!("# Allocated {} frames on {}", allocated, node_id);
    }
}

unsafe impl Allocator for MyAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let node_id = NODE_ID.fetch_add(1, Ordering::SeqCst);
        let node_offset = (node_id - 1) as u64 * LARGE_PAGE_SIZE as u64 * MAX_FRAMES;
        MyAllocator::allocate_pages(node_id);
        info!("# Allocating {:?}", layout);
        if layout.size() > LARGE_PAGE_SIZE * MAX_FRAMES as usize {
            return Err(AllocError);
        }

        let slice = unsafe { from_raw_parts_mut((BASE + node_offset) as *mut u8, layout.size()) };
        Ok(NonNull::from(slice))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        info!("# Deallocating {:?}", layout);
        /*for i in 0..MAX_FRAMES {
            vibrio::syscalls::VSpace::unmap((BASE + (i * LARGE_PAGE_SIZE as u64)) as u64, LARGE_PAGE_SIZE as u64)
                .expect("Failed to unmap base page");
        }*/
    }
}
