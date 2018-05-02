use alloc::boxed::Box;

use ::arch::memory::{BASE_PAGE_SIZE};

pub type StackMemory = [u8; BASE_PAGE_SIZE as usize * 32];

pub trait StackProvider<'a> {
    fn allocate_stack(&mut self) -> Option<&mut StackMemory>;
    fn release_stack(&mut self, &mut StackMemory);
}

/// A task's stack. The name "Stack" is a vestige of segmented stacks.
pub struct Stack {
    buf: Box<StackMemory>,
}

impl Stack {
    
    /// Allocate a new stack of `size`. If size = 0, this will fail. Use
    /// `dummy_stack` if you want a zero-sized stack.
    pub fn new() -> Stack {
        let s: Box<StackMemory> = box [0; BASE_PAGE_SIZE as usize * 32];
        Stack { buf: s }
    }

    pub fn guard(&self) -> *const usize {
        (self.start() as usize + BASE_PAGE_SIZE as usize) as *const usize
    }

    /// Point to the low end of the allocated stack
    pub fn start(&self) -> *const usize {
        self.buf.as_ptr() as *const usize
    }

    /// Point one usize beyond the high end of the allocated stack
    pub fn end(&self) -> *const u8 {
        unsafe {
            let ptr = self.buf.as_ptr();
            ptr.offset(self.buf.len() as isize)
        }
    }
}

/*
fn protect_last_page(stack: &StackMemory) -> bool {
    true
}
*/
