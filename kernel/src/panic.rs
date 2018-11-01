use core::alloc::Layout;
use core::panic::PanicInfo;

use arch;
use backtracer;
use ExitReason;

fn backtrace_format(count: usize, frame: &backtracer::Frame) -> bool {
    let kernel_binary = arch::KERNEL_BINARY.lock();
    let ip = frame.ip();

    sprint!("frame #{:<2} - {:#02$x}", count, ip as usize, 20);
    let mut resolved = false;

    // Resolve this instruction pointer to a symbol name
    if kernel_binary.is_some() {
        backtracer::resolve(&*kernel_binary.unwrap(), ip, |symbol| {
            if !resolved {
                resolved = true;
            } else {
                sprint!("                                ");
            }
            if let Some(name) = symbol.name() {
                if name.as_bytes().len() == 0 {
                    sprint!(" - <empty>");
                } else {
                    sprint!(" - {}", name);
                }
            } else {
                sprint!(" - <unknown>");
            }
            sprintln!("");
        });
    }
    if !resolved {
        sprintln!(" - <no info>");
    }
    true
}

#[inline(always)]
pub fn backtrace_from(rbp: u64, rsp: u64, rip: u64) {
    sprintln!("Backtrace:");
    let mut count = 0;
    backtracer::trace_from(backtracer::EntryPoint::new(rbp, rsp, rip), |frame| {
        count += 1;
        backtrace_format(count, frame)
    });
}

#[inline(always)]
fn backtrace() {
    sprintln!("Backtrace:");
    let mut count = 0;
    backtracer::trace(|frame| {
        count += 1;
        backtrace_format(count, frame)
    });
}

#[cfg_attr(target_os = "none", panic_handler)]
#[no_mangle]
pub fn panic_impl(info: &PanicInfo) -> ! {
    sprint!("System panic encountered");
    if let Some(message) = info.message() {
        sprint!(": '{}'", message);
    }
    if let Some(location) = info.location() {
        sprintln!(" in {}:{}", location.file(), location.line());
    } else {
        sprintln!("");
    }

    backtrace();

    arch::debug::shutdown(ExitReason::KernelPanic);
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum _Unwind_Reason_Code {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8,
}

#[allow(non_camel_case_types)]
pub struct _Unwind_Context;

#[allow(non_camel_case_types)]
pub type _Unwind_Action = u32;
static _UA_SEARCH_PHASE: _Unwind_Action = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct _Unwind_Exception {
    exception_class: u64,
    exception_cleanup: fn(_Unwind_Reason_Code, *const _Unwind_Exception),
    private: [u64; 2],
}

#[cfg_attr(target_os = "none", lang = "eh_personality")]
#[no_mangle]
pub fn rust_eh_personality(
    _version: isize,
    _actions: _Unwind_Action,
    _exception_class: u64,
    _exception_object: &_Unwind_Exception,
    _context: &_Unwind_Context,
) -> _Unwind_Reason_Code {
    loop {}
}

#[no_mangle]
#[cfg_attr(target_os = "none", lang = "oom")]
pub fn oom(layout: Layout) -> ! {
    sprintln!(
        "OOM: Unable to satisfy allocation request for size {} with alignment {}.",
        layout.size(),
        layout.align()
    );
    backtrace();

    arch::debug::shutdown(ExitReason::OutOfMemory);
}

#[no_mangle]
#[allow(non_snake_case)]
pub fn _Unwind_Resume() {
    loop {}
}
