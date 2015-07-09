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

    full_pages: usize,
    full: Option<&'a mut SlabPage<'a>>,
}

impl<'a> SlabAllocator<'a> {

    fn add<'b>(&'b mut self, amount: usize) {
        let mut fm = mm::fmanager.lock();

        match fm.allocate_frame(BASE_PAGE_SIZE) {
            Some(frame) => {

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

    pub fn allocate(&'a mut self, alignment: usize) -> *mut u8 {

        let mut full_page = None;
        for slab_page in self.allocateable.iter_mut() {
            match slab_page.allocate(alignment) {
                None => { () },
                Some(obj) => {
                    if slab_page.is_full() {
                        full_page = Some(slab_page);
                    }

                    return (obj as *mut u8);
                }
            };
        }

        match full_page {
            Some(page) => {
                //self.remove_from_list(page);
                SlabAllocator::insert_front(&mut self.full, page);
            },
            None => ()
        };

        (EMPTY as *mut u8)


    }

    fn remove_from_list(&mut self, p: &mut SlabPage) {

    }

    fn insert_front(head: &'a mut Option<&'a mut SlabPage<'a>>, new_head: &'a mut SlabPage<'a>) {

        match *head {
            None => { *head = Some(new_head); }
            Some(ref mut current_head) => {
                current_head.meta.prev = Rawlink::some(new_head);
                new_head.meta.next = Rawlink::some(current_head);
                *current_head = new_head;
            }
        }
    }

    /*    return buf ;

        match self.allocateable {
            None => { return EMPTY as *mut u8; }
            Some(p) => {
                if p.can_allocate(alignment) {
                    let buf = p.allocate(alignment);
                    if p.is_full() {
                        // Move out of list
                        match p.meta.prev {
                            Some(prev) => { prev.meta.next = p.meta.next }
                            None => { self.allocateable = p.meta.next }
                        };
                        match p.meta.next {
                            Some(next) => { next.meta.prev = p.meta.prev }
                            None => { p.meta.prev = None }
                        };

                        // Add to allocated
                        self.allocated = Some(p);
                    }

                    return buf as *mut u8;
                }

                return EMPTY as *mut u8;
            }
        }
    }*/

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

    pub fn can_allocate(&self, alignment: usize) -> bool {
        false
    }

    pub fn allocate(&self, alignment: usize) -> Option<*mut u8> {
        None
    }

    pub fn is_full(&self) -> bool {
        true
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
    let mut allocator = SlabAllocator{
        size: 40,
        allocateable_elements: 0,
        allocateable: None,
        full_pages: 0,
        full: None
    };

    allocator.add(4);
    allocator.allocate(align)
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