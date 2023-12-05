use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};

#[derive(Clone, Copy)]
pub struct MyAllocator;

unsafe impl Allocator for MyAllocator {
    fn allocate(&self, _layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unimplemented!("MyAllocator does not support allocate");
    }

    unsafe fn deallocate(&self, _ptr: NonNull<u8>, _layout: Layout) {
        unimplemented!("MyAllocator does not support deallocate");
    }
}
