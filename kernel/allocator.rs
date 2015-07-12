use prelude::*;

use core::mem;
use core::ptr;
use mm;

pub const EMPTY: *mut () = 0x1 as *mut ();

use slabmalloc::{ZoneAllocator, SlabAllocator};
use mutex::{Mutex};

static zone_allocator: Mutex<ZoneAllocator> =
    mutex!(ZoneAllocator { slabs: [
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
        SlabAllocator{size: 0, allocateable_elements: 0, allocateable: None},
    ]});


/// Return a pointer to `size` bytes of memory aligned to `align`.
///
/// On failure, return a null pointer.
///
/// Behavior is undefined if the requested size is 0 or the alignment is not a
/// power of 2. The alignment must be no larger than the largest supported page
/// size on the platform.
#[no_mangle]
fn rust_allocate(size: usize, align: usize) -> *mut u8 {
    log!("size {} align {}", size, align);
    assert!(align.is_power_of_two());

    let mut za = zone_allocator.lock();
    match za.allocate(size, align) {
        Some(buf) => buf,
        None => EMPTY as *mut u8
    }
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
    let mut za = zone_allocator.lock();
    za.deallocate(ptr, old_size, align);
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