use core::ptr;
use core::raw;
use core::raw::{Repr};

use x86::paging::{BASE_PAGE_SIZE};

pub type StackMemory = [u8; BASE_PAGE_SIZE as usize * 32];

pub trait StackProvider<'a> {
    fn allocate_stack(&mut self) -> Option<&mut StackMemory>;
    fn release_stack(&mut self, &mut StackMemory);
}

/// A task's stack. The name "Stack" is a vestige of segmented stacks.
pub struct Stack<'a> {
    buf: Option<&'a mut StackMemory>,
}

impl<'a> Stack<'a> {
    
    /// Allocate a new stack of `size`. If size = 0, this will fail. Use
    /// `dummy_stack` if you want a zero-sized stack.
    pub fn new() -> Stack<'a> {
        /*let stack = match StackMemory::new(size, &[MapReadable, MapWritable,
                                         MapNonStandardFlags(STACK_FLAGS)]) {
            Ok(map) => map,
            Err(e) => panic!("mmap for stack of size {} failed: {}", size, e)
        };

        if !protect_last_page(&stack) {
            panic!("Could not memory-protect guard page. stack={}, errno={}",
                  stack.data(), errno());
        }*/

        Stack {
            buf: None,
        }
    }

    pub fn guard(&self) -> *const usize {
        (self.start() as usize + BASE_PAGE_SIZE as usize) as *const usize
    }

    /// Point to the low end of the allocated stack
    pub fn start(&self) -> *const usize {
        self.buf.as_ref().map(|buf| {
        	let repr: raw::Slice<u8> = buf.repr();
            repr.data as *const usize
        }).unwrap_or(ptr::null())
    }

    /// Point one usize beyond the high end of the allocated stack
    pub fn end(&self) -> *const usize {
    	unsafe {
	        self.buf.as_ref().map(|buf| {
				let repr: raw::Slice<u8> = buf.repr();
	            repr.data.offset(repr.len as isize) as *const usize
	        }).unwrap_or(ptr::null())
        }
    }
}

fn protect_last_page(stack: &StackMemory) -> bool {
	true
}
