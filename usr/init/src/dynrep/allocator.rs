use alloc::sync::Arc;
use core::slice::from_raw_parts_mut;
use lazy_static::lazy_static;

use kpi::system::NodeId;
use spin::Mutex;
use x86::bits64::paging::LARGE_PAGE_SIZE;

use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};

pub const BASE: u64 = 0x0510_0000_0000;
pub const MAX_FRAMES: u64 = 600;

lazy_static! {
    pub(crate) static ref ALLOC_AFFINITY: Arc<Mutex<NodeId>> = Arc::new(Mutex::new(0));
}

#[derive(Clone, Copy)]
pub struct MyAllocator;

impl MyAllocator {
    fn allocate_pages(node_id: NodeId) {
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
            log::trace!(
                "large frame id={:?}, paddr={:?}, mid={:?}",
                frame_id,
                paddr,
                node_id
            );

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
    }
}

unsafe impl Allocator for MyAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Check argument
        log::info!("{:?}", layout);
        if layout.size() > LARGE_PAGE_SIZE * MAX_FRAMES as usize {
            return Err(AllocError);
        }

        // Grab affinity lock
        let affinity = (*ALLOC_AFFINITY).lock();
        log::info!("Affinity for alloc is: {:?}", *affinity + 1);

        // Allocate and map pages
        MyAllocator::allocate_pages(*affinity + 1);

        // Get ptr to mapped memory
        let node_offset = *affinity as u64 * LARGE_PAGE_SIZE as u64 * MAX_FRAMES;
        let slice = unsafe { from_raw_parts_mut((BASE + node_offset) as *mut u8, layout.size()) };

        log::info!("Finished allocating on {:?}", *affinity + 1);
        Ok(NonNull::from(slice))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        log::info!("Deallocating {:?}", layout);
        /*for i in 0..MAX_FRAMES {
            vibrio::syscalls::VSpace::unmap((BASE + (i * LARGE_PAGE_SIZE as u64)) as u64, LARGE_PAGE_SIZE as u64)
                .expect("Failed to unmap base page");
        }*/
    }
}
