use prelude::*;
use core::mem::{transmute};

use mm;
use ::arch::memory::{paddr_to_kernel_vaddr, CACHE_LINE_SIZE, BASE_PAGE_SIZE, VAddr};

pub const EMPTY: *mut () = 0x1 as *mut ();


/// One slab allocator allocated elements of fixed sizes using raw pages.
pub struct SlabAllocator<'a> {
    size: usize,
    free: Option<&'a mut SlabPage<'a>>,
    allocated: Option<&'a mut SlabPage<'a>>,
}

impl<'a> SlabAllocator<'a> {

    fn add(self, amount: usize) {
        let mut fm = mm::fmanager.lock();

        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                let mut sp = transmute::<VAddr, &mut SlabPage>(
                    paddr_to_kernel_vaddr(frame.base)
                );

                match self.free {
                    None => { self.free = Some(sp); }
                    Some(fp) => {
                        sp.meta.next = Some(fp);
                        fp.meta.prev = Some(sp);
                        self.free = Some(sp);
                    }
                }
            },
            None => ()
        }
    }

    pub fn allocate(self, alignment: usize) -> *mut u8 {
        match self.free {
            None => { return EMPTY; }
            Some(p) => {
                if p.can_allocate(alignment) {
                    let buf = p.allocate(alignment);
                    if p.is_full() {

                        // Move out of list
                        match p.meta.prev {
                            Some(prev) => { prev.meta.next = p.meta.next }
                            None => { self.free = p.meta.next }
                        };
                        match p.meta.next {
                            Some(next) => { next.meta.prev = p.meta.prev }
                            None => { p.meta.prev = None }
                        };

                        // Add to allocated
                        self.allocated = Some(p);
                    }

                    buf
                }

                EMPTY
            }
        }
    }

    pub fn deallocate(ptr: *mut u8, alignment: usize) {

    }

}

pub struct SlabPage<'a> {
    data: [u8; 4096 - 64],
    meta: SlabPageMeta<'a>
}

impl<'a> SlabPage<'a> {

    pub fn can_allocate(self, alignment: usize) -> bool {
        false
    }

    pub fn allocate(self, alignment: usize) -> *mut u8 {
        EMPTY
    }

    pub fn is_full(self) -> bool {
        true
    }


}

/// Meta-data stored at the end of a page to track allocations within the page.
/// This structure should fit exactly in a single cache-line.
/// XXX: No static size_of to enforce this...
pub struct SlabPageMeta<'a> {
    prev: Option<&'a mut SlabPage<'a>>,
    next: Option<&'a mut SlabPage<'a>>,
    // Note: with only 48 bits we do waste some space for the
    // 8 bytes slab allocator. But 12 bytes on-wards is ok.
    bitfield: [u8; CACHE_LINE_SIZE - 16]
}



/// Return a pointer to `size` bytes of memory aligned to `align`.
///
/// On failure, return a null pointer.
///
/// Behavior is undefined if the requested size is 0 or the alignment is not a
/// power of 2. The alignment must be no larger than the largest supported page
/// size on the platform.
#[no_mangle]
fn rust_allocate(size: usize, align: usize) -> *mut u8 {
    EMPTY as *mut u8
}


/// Deallocates the memory referenced by `ptr`.
///
/// The `ptr` parameter must not be null.
///
/// The `old_size` and `align` parameters are the parameters that were used to
/// create the allocation referenced by `ptr`. The `old_size` parameter may be
/// any value in range_inclusive(requested_size, usable_size).
#[no_mangle]
fn rust_deallocate(ptr: *mut u8, old_size: usize, align: usize) {

}

/// Resize the allocation referenced by `ptr` to `size` bytes.
///
/// On failure, return a null pointer and leave the original allocation intact.
///
/// If the allocation was relocated, the memory at the passed-in pointer is
/// undefined after the call.
///
/// Behavior is undefined if the requested size is 0 or the alignment is not a
/// power of 2. The alignment must be no larger than the largest supported page
/// size on the platform.
///
/// The `old_size` and `align` parameters are the parameters that were used to
/// create the allocation referenced by `ptr`. The `old_size` parameter may be
/// any value in range_inclusive(requested_size, usable_size).
#[no_mangle]
fn rust_reallocate(ptr: *mut u8, old_size: usize, size: usize, align: usize) -> *mut u8 {
    EMPTY as *mut u8
}

/// Resize the allocation referenced by `ptr` to `size` bytes.
///
/// If the operation succeeds, it returns `usable_size(size, align)` and if it
/// fails (or is a no-op) it returns `usable_size(old_size, align)`.
///
/// Behavior is undefined if the requested size is 0 or the alignment is not a
/// power of 2. The alignment must be no larger than the largest supported page
/// size on the platform.
///
/// The `old_size` and `align` parameters are the parameters that were used to
/// create the allocation referenced by `ptr`. The `old_size` parameter may be
/// any value in range_inclusive(requested_size, usable_size).
#[no_mangle]
fn rust_reallocate_inplace(ptr: *mut u8, old_size: usize, size: usize,
                           align: usize) -> usize {
    0
}


#[no_mangle]
fn rust_usable_size(size: usize, align: usize) -> usize {
    0
}

#[no_mangle]
fn rust_stats_print() {
    log!("rust stats?");
}