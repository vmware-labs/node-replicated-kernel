use core::mem;
use core::ptr;

pub const EMPTY: *mut () = 0x1 as *mut ();
use slabmalloc::{ZoneAllocator};

pub static mut zone_allocator: Option<&'static mut ZoneAllocator<'static>> = None;

/// Return a pointer to `size` bytes of memory aligned to `align`.
///
/// On failure, return a null pointer.
///
/// Behavior is undefined if the requested size is 0 or the alignment is not a
/// power of 2. The alignment must be no larger than the largest supported page
/// size on the platform.
#[no_mangle]
pub extern fn __rust_allocate(size: usize, align: usize) -> *mut u8 {
    log!("size {} align {}", size, align);
    assert!(align.is_power_of_two());

    unsafe {
        match zone_allocator.as_mut() {
            Some(z) => {
                match z.allocate(size, align) {
                    Some(buf) => buf,
                    None => EMPTY as *mut u8,
                }
            },
            None => EMPTY as *mut u8,
        }
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
pub extern fn __rust_deallocate(ptr: *mut u8, old_size: usize, align: usize) {
    log!("deallocate old_size={}", old_size);
    unsafe {
        zone_allocator.as_mut().map(|z| { z.deallocate(ptr, old_size, align); });
    }
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
pub extern fn __rust_reallocate(ptr: *mut u8, old_size: usize, size: usize, align: usize) -> *mut u8 {
    log!("reallocate old={} new={}", old_size, size);
    unsafe {
        match zone_allocator.as_mut() {
            Some(z) => {
                match z.reallocate(ptr, old_size, size, align) {
                    Some(buf) => buf,
                    None => EMPTY as *mut u8,
                }
            },
            None => EMPTY as *mut u8,
        }
    }
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
pub extern fn __rust_reallocate_inplace(ptr: *mut u8, old_size: usize, size: usize,
                           align: usize) -> usize {
    log!("reallocate inplcae");

    0
}


#[no_mangle]
pub extern fn __rust_usable_size(size: usize, align: usize) -> usize {
    log!("usable size");

    0
}

#[no_mangle]
fn __rust_stats_print() {
    log!("rust stats?");
}