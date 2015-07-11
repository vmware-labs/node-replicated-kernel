use prelude::*;
use core::mem;
use core::ptr;

use mm;
use ::arch::memory::{paddr_to_kernel_vaddr, CACHE_LINE_SIZE, BASE_PAGE_SIZE, VAddr};

pub const EMPTY: *mut () = 0x1 as *mut ();

struct Rawlink<T> {
    p: *mut T,
}

/// Rawlink is a type like Option<T> but for holding a raw pointer
impl<T> Rawlink<T> {

    /// Like Option::None for Rawlink
    fn none() -> Rawlink<T> {
        Rawlink{ p: ptr::null_mut() }
    }

    /// Like Option::Some for Rawlink
    fn some(n: &mut T) -> Rawlink<T> {
        Rawlink{p: n}
    }

    /// Convert the `Rawlink` into an Option value
    ///
    /// **unsafe** because:
    ///
    /// - Dereference of raw pointer.
    /// - Returns reference of arbitrary lifetime.
    unsafe fn resolve<'a>(&self) -> Option<&'a T> {
        self.p.as_ref()
    }

    /// Convert the `Rawlink` into an Option value
    ///
    /// **unsafe** because:
    ///
    /// - Dereference of raw pointer.
    /// - Returns reference of arbitrary lifetime.
    unsafe fn resolve_mut<'a>(&mut self) -> Option<&'a mut T> {
        self.p.as_mut()
    }

    /// Return the `Rawlink` and replace with `Rawlink::none()`
    fn take(&mut self) -> Rawlink<T> {
        mem::replace(self, Rawlink::none())
    }
}

/// One slab allocator allocated elements of fixed sizes using raw pages.
pub struct SlabAllocator<'a> {
    pub size: usize,

    allocateable_elements: usize,
    allocateable: Option<&'a mut SlabPage<'a>>,
}

impl<'a> SlabAllocator<'a> {

    fn refill_slab<'b>(&'b mut self, amount: usize) {
        let mut fm = mm::fmanager.lock();

        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {
                log!("Add new frame {:?}", frame);
                let mut new_head = unsafe {
                    mem::transmute::<VAddr, &'a mut SlabPage>(
                        paddr_to_kernel_vaddr(frame.base))
                };

                SlabAllocator::insert_front(&mut self.allocateable, new_head);
                self.allocateable_elements += 1;
            },
            None => ()
        }
    }

    fn try_allocate<'b>(&'b mut self, alignment: usize) -> Option<*mut u8> {

        for slab_page in self.allocateable.iter_mut() {
            log!("slab page");
            match slab_page.allocate(self.size, alignment) {
                None => { () },
                Some(obj) => {
                    log!("got something");
                    return Some(obj as *mut u8);
                }
            };
        }

        None
    }

    pub fn allocate(&'a mut self, alignment: usize) -> Option<*mut u8> {
        match self.try_allocate(alignment) {
            None => {
                self.refill_slab(1);
                self.try_allocate(alignment)
            }
            Some(obj) => Some(obj)
        }
    }

    fn remove_from_list<'b>(head: &'b mut Option<&'a mut SlabPage<'a>>, p: &'a mut SlabPage<'a>) {
        unsafe {
            match p.meta.prev.resolve_mut() {
                None => {
                    match p.meta.next.resolve_mut() {
                        None => { *head = None; },
                        Some(next_page) => { *head = Some(next_page) }
                    }
                },
                Some(prev_page) => {
                    match p.meta.next.resolve_mut() {
                        None => { prev_page.meta.next = Rawlink::none(); },
                        Some(next_page) => { prev_page.meta.next = Rawlink::some(next_page) }
                    }
                }
            }
        }
    }

    fn insert_front<'b>(head: &'b mut Option<&'a mut SlabPage<'a>>, new_head: &'a mut SlabPage<'a>) {

        match *head {
            None => { *head = Some(new_head); }
            Some(ref mut current_head) => {
                current_head.meta.prev = Rawlink::some(new_head);
                new_head.meta.next = Rawlink::some(current_head);
                *current_head = new_head;
            }
        }
    }

    pub fn deallocate(ptr: *mut u8, alignment: usize) {

    }

}

pub struct SlabPageIter<'a> {
    head: Rawlink<SlabPage<'a>>,
    nelem: usize,
}

impl<'a> Iterator for SlabPageIter<'a> {
    type Item = &'a mut SlabPage<'a>;

    #[inline]
    fn next(&mut self) -> Option<&'a mut SlabPage<'a>> {
        if self.nelem == 0 {
            return None;
        }

        unsafe {
            self.head.resolve_mut().map(|next| {
                self.nelem -= 1;
                //self.head = next.meta.next;
                next
            })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.nelem, Some(self.nelem))
    }
}

pub struct SlabPage<'a> {
    data: [u8; 4096 - 64],
    meta: SlabPageMeta<'a>
}

impl<'a> SlabPage<'a> {

    fn first_fit(&self, size: usize, alignment: usize) -> Option<(usize, usize)> {
        for (base_idx, b) in self.meta.bitfield.iter().enumerate() {
            for bit_idx in 0..8 {
                let idx: usize = base_idx * 8 + bit_idx;
                let addr: usize = ((self as *const SlabPage) as usize) + idx * size;
                log!("{} {} {:x} {}", idx, b, addr, addr % alignment == 0);

                let alignment_ok = addr % alignment == 0;
                let block_is_free = b & (1 << bit_idx) == 0;
                if alignment_ok && block_is_free {
                    return Some((idx, addr));
                }
            }
        }
        None
    }

    fn set_bit(&mut self, idx: usize) {
        let base_idx = idx / 8;
        let bit_idx = idx % 8;
        self.meta.bitfield[base_idx] |= 1 << bit_idx;
    }

    pub fn allocate(&mut self, size: usize, alignment: usize) -> Option<*mut u8> {
        match self.first_fit(size, alignment) {
            Some((idx, addr)) => {
                self.set_bit(idx);
                Some(unsafe { mem::transmute::<usize, *mut u8>(addr) })
            }
            None => None
        }
    }

    pub fn is_full(&self) -> bool {
        self.meta.bitfield.iter().filter(|&x| *x != 0xff).count() == 0
    }

}

/// Meta-data stored at the end of a page to track allocations within the page.
/// This structure should fit exactly in a single cache-line.
/// XXX: No static size_of to enforce this...
pub struct SlabPageMeta<'a> {
    prev: Rawlink<SlabPage<'a>>,
    next: Rawlink<SlabPage<'a>>,
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
    log!("size {} align {}", size, align);
    assert!(align.is_power_of_two());
    let mut allocator = SlabAllocator{
        size: 40,
        allocateable_elements: 0,
        allocateable: None,
    };

    match allocator.allocate(align) {
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