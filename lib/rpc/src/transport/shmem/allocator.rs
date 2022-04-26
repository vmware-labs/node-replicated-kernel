use alloc::alloc::handle_alloc_error;
use core::alloc::Layout;
use core::alloc::{AllocError, Allocator};
use core::ptr::NonNull;
use core::slice::from_raw_parts_mut;
use core::sync::atomic::{AtomicU64, Ordering};

pub struct ShmemAllocator {
    base: u64,
    size: u64,
    next: AtomicU64,
}

impl ShmemAllocator {
    pub fn new(base: u64, size: u64) -> ShmemAllocator {
        ShmemAllocator {
            base,
            size,
            next: AtomicU64::new(base),
        }
    }

    fn try_alloc(&self, cur_next: u64, size: usize) -> bool {
        if cur_next + size as u64 > self.base + self.size {
            return false;
        }

        self.next
            .compare_exchange_weak(
                cur_next,
                cur_next + size as u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

unsafe impl Allocator for ShmemAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = self.next.load(Ordering::Relaxed);
        match self.try_alloc(ptr, layout.size()) {
            true => unsafe {
                Ok(NonNull::new_unchecked(from_raw_parts_mut(
                    (ptr) as *mut u8,
                    layout.size(),
                )))
            },
            false => handle_alloc_error(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        log::debug!("deallocate: {:?}", ptr);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_allocator() {
        let base = 0x1000;
        let size = 0x2000;
        let allocator = ShmemAllocator::new(base, size);
        let layout = Layout::from_size_align(0x1000, 1).unwrap();
        let ptr = allocator.allocate(layout).unwrap();
        assert_eq!((ptr.cast().as_ptr() as *const u8) as u64, base);
        assert_eq!(allocator.next.load(Ordering::Relaxed), base + 0x1000);
    }

    #[test]
    fn test_allocator_overflow() {
        let base = 0x1000;
        let size = 0x2000;
        let allocator = ShmemAllocator::new(base, size);
        let layout = Layout::from_size_align(0x1000, 1).unwrap();
        let ptr = allocator.allocate(layout).unwrap();
        assert_eq!((ptr.cast().as_ptr() as *const u8) as u64, base);
        assert_eq!(allocator.next.load(Ordering::Relaxed), base + 0x1000);
        let ptr = allocator.allocate(layout).unwrap();
        assert_eq!((ptr.cast().as_ptr() as *const u8) as u64, base + 0x1000);
        assert_eq!(allocator.next.load(Ordering::Relaxed), base + 0x2000);
    }
}
