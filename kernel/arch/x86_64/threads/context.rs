use core::ops::{FnOnce};
use super::stack::{Stack};

macro_rules! rtdebug{
	( $($arg:tt)* ) => ({
		use core::fmt::Write;
        use klogger::{Writer};
		let _ = write!(&mut Writer::get(module_path!()), $($arg)*);
	})
}

pub struct Context {
    /// Hold the registers while the task or scheduler is suspended
    regs: Registers,
    /// Lower bound and upper bound for the stack
    stack_bounds: Option<(usize, usize)>,
}

pub type InitFn = extern "C" fn(usize, *mut (), *mut ()) -> !;
pub type ThreadFn = FnOnce(usize) -> usize;

impl Context {
    pub fn empty() -> Context {
        Context {
            regs: new_regs(),
            stack_bounds: None,
        }
    }

    /// Create a new context that will resume execution by running proc()
    ///
    /// The `init` function will be run with `arg` and the `start` procedure
    /// split up into code and env pointers. It is required that the `init`
    /// function never return.
    pub fn new(init: InitFn, arg: usize, start: fn(usize) -> usize, stack: &mut Stack) -> Context {

        let sp: *const usize = stack.end();
        let sp: *mut usize = sp as *mut usize;
        // Save and then immediately load the current context,
        // which we will then modify to call the given function when restored
        let mut regs = new_regs();

        initialize_call_frame(&mut regs, init, arg, start, sp);

        // Scheduler tasks don't have a stack in the "we allocated it" sense,
        // but rather they run on pthreads stacks. We have complete control over
        // them in terms of the code running on them (and hopefully they don't
        // overflow). Additionally, their coroutine stacks are listed as being
        // zero-length, so that's how we detect what's what here.
        let stack_base: *const usize = stack.start();
        let bounds = if sp as usize == stack_base as usize {
            None
        } else {
            Some((stack_base as usize, sp as usize))
        };

        return Context {
            regs: regs,
            stack_bounds: bounds,
        }
    }

    /* Switch contexts

    Suspend the current execution context and resume another by
    saving the registers values of the executing thread to a Context
    then loading the registers from a previously saved Context.
    */
    pub fn swap(out_context: &mut Context, in_context: &Context) {
        rtdebug!("swapping contexts");
        let out_regs: &mut Registers = match out_context {
            &mut Context { regs: ref mut r, .. } => r
        };
        let in_regs: &Registers = match in_context {
            &Context { regs: ref r, .. } => r
        };

        rtdebug!("noting the stack limit and doing raw swap");

        unsafe {
        	/*
            // Right before we switch to the new context, set the new context's
            // stack limit in the OS-specified TLS slot. This also  means that
            // we cannot call any more rust functions after record_stack_bounds
            // returns because they would all likely fail due to the limit being
            // invalid for the current task. Lucky for us `rust_swap_registers`
            // is a C function so we don't have to worry about that!
            match in_context.stack_bounds {
                Some((lo, hi)) => stack::record_rust_managed_stack_bounds(lo, hi),
                // If we're going back to one of the original contexts or
                // something that's possibly not a "normal task", then reset
                // the stack limit to 0 to make morestack never fail
                None => stack::record_rust_managed_stack_bounds(0, usize::MAX),
            }*/
            rust_swap_registers(out_regs, in_regs)
        }
    }
}

#[link(name = "context_switch", kind = "static")]
extern {
    fn rust_swap_registers(out_regs: *mut Registers, in_regs: *const Registers);
}

// Register contexts used in various architectures
//
// These structures all represent a context of one task throughout its
// execution. Each struct is a representation of the architecture's register
// set. When swapping between tasks, these register sets are used to save off
// the current registers into one struct, and load them all from another.
//
// Note that this is only used for context switching, which means that some of
// the registers may go unused. For example, for architectures with
// callee/caller saved registers, the context will only reflect the callee-saved
// registers. This is because the caller saved registers are already stored
// elsewhere on the stack (if it was necessary anyway).
//
// Additionally, there may be fields on various architectures which are unused
// entirely because they only reflect what is theoretically possible for a
// "complete register set" to show, but user-space cannot alter these registers.
// An example of this would be the segment selectors for x86.
//
// These structures/functions are roughly in-sync with the source files inside
// of src/rt/arch/$arch. The only currently used function from those folders is
// the `rust_swap_registers` function, but that's only because for now segmented
// stacks are disabled.


#[repr(C)]
struct Registers {
    gpr:[u64; 10],
}

fn new_regs() -> Registers {
    Registers { gpr: [0; 10] }
}

#[cfg(target_arch = "x86_64")]
fn initialize_call_frame<F>(regs: &mut Registers, fptr: InitFn, arg: usize,
                         procedure: F, sp: *mut usize) where F: FnOnce(usize) -> usize {
    extern { fn rust_bootstrap_green_task(); }

    // Redefinitions from rt/arch/x86_64/regs.h
    static RUSTRT_RSP: usize = 1;
    static RUSTRT_IP: usize = 8;
    static RUSTRT_RBP: usize = 2;
    static RUSTRT_R12: usize = 4;
    static RUSTRT_R13: usize = 5;
    static RUSTRT_R14: usize = 6;
    static RUSTRT_R15: usize = 7;

    let sp = align_down(sp);
    let sp = mut_offset(sp, -1);

    // The final return address. 0 indicates the bottom of the stack
    unsafe { *sp = 0; }

    rtdebug!("creating call frame");
    rtdebug!("fptr {:#x}", fptr as usize);
    rtdebug!("arg {:#x}", arg);
    rtdebug!("sp {:?}", sp);

    // These registers are frobbed by rust_bootstrap_green_task into the right
    // location so we can invoke the "real init function", `fptr`.
    regs.gpr[RUSTRT_R12] = arg as u64;

    //assert!("fixme {}", arg);
    //regs.gpr[RUSTRT_R13] = procedure.code as u64;
    //regs.gpr[RUSTRT_R14] = procedure.env as u64;
    
    regs.gpr[RUSTRT_R15] = fptr as u64;

    // These registers are picked up by the regular context switch paths. These
    // will put us in "mostly the right context" except for frobbing all the
    // arguments to the right place. We have the small trampoline code inside of
    // rust_bootstrap_green_task to do that.
    regs.gpr[RUSTRT_RSP] = sp as u64;
    regs.gpr[RUSTRT_IP] = rust_bootstrap_green_task as u64;

    // Last base pointer on the stack should be 0
    regs.gpr[RUSTRT_RBP] = 0;
}

fn align_down(sp: *mut usize) -> *mut usize {
    let sp = (sp as usize) & !(16 - 1);
    sp as *mut usize
}

// ptr::mut_offset is positive ints only
#[inline]
pub fn mut_offset<T>(ptr: *mut T, count: usize) -> *mut T {
    use core::mem::size_of;
    (ptr as usize + count * (size_of::<T>() as usize)) as *mut T
}