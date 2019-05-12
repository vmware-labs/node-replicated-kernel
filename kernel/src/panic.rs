use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::arch;
use crate::kcb;
use crate::ExitReason;
use backtracer;

use alloc::rc::Rc;

use addr2line;
use addr2line::gimli;
use addr2line::Context;

fn new_ctxt(file: &elfloader::ElfBinary) -> Option<Context> {
    let endian = gimli::RunTimeEndian::Little;

    fn load_section<S, Endian>(elf: &elfloader::ElfBinary, endian: Endian) -> S
    where
        S: gimli::Section<gimli::EndianRcSlice<Endian>>,
        Endian: gimli::Endianity,
    {
        let data = elf
            .file
            .find_section_by_name(S::section_name())
            .map(|s| s.raw_data(&elf.file))
            .unwrap_or(&[]);
        S::from(gimli::EndianRcSlice::new(Rc::from(&*data), endian))
    }

    let debug_abbrev: gimli::DebugAbbrev<_> = load_section(file, endian);
    let debug_addr: gimli::DebugAddr<_> = load_section(file, endian);
    let debug_info: gimli::DebugInfo<_> = load_section(file, endian);
    let debug_line: gimli::DebugLine<_> = load_section(file, endian);
    let debug_line_str: gimli::DebugLineStr<_> = load_section(file, endian);
    let debug_ranges: gimli::DebugRanges<_> = load_section(file, endian);
    let debug_rnglists: gimli::DebugRngLists<_> = load_section(file, endian);
    let debug_str: gimli::DebugStr<_> = load_section(file, endian);
    let debug_str_offsets: gimli::DebugStrOffsets<_> = load_section(file, endian);
    let default_section = gimli::EndianRcSlice::new(Rc::from(&[][..]), endian);

    Context::from_sections(
        debug_abbrev,
        debug_addr,
        debug_info,
        debug_line,
        debug_line_str,
        debug_ranges,
        debug_rnglists,
        debug_str,
        debug_str_offsets,
        default_section,
    )
    .ok()
}

fn backtrace_format(
    context: Option<&Context>,
    relocated_offset: u64,
    count: usize,
    frame: &backtracer::Frame,
) -> bool {
    let ip = frame.ip();
    sprint!("frame #{:<2} - {:#02$x}", count, ip as usize, 20);
    let mut resolved = false;

    backtracer::resolve(context, relocated_offset, ip, |symbol| {
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
                if let Some(file) = symbol.filename() {
                    sprint!(" ({}", file);
                    if let Some(line) = symbol.lineno() {
                        sprint!(":{})", line);
                    } else {
                        sprint!(")");
                    }
                }
            }
        } else {
            sprint!(" - <unknown>");
        }
        sprintln!("");
    });

    if !resolved {
        sprintln!(" - <no info>");
    }
    true
}

#[inline(always)]
pub fn backtrace_from(rbp: u64, rsp: u64, rip: u64) {
    sprintln!("Backtrace:");
    let kernel_info = kcb::try_get_kcb().map(|k| {
        (
            k.kernel_binary(),
            k.kernel_args().kernel_elf_offset.as_u64(),
        )
    });
    let (elf_data, relocated_offset) = kernel_info.expect("Don't have kernel info");
    let elf_binary =
        elfloader::ElfBinary::new("kernel", &elf_data).expect("Can't parse kernel Binary");
    let context = new_ctxt(&elf_binary);

    let mut count = 0;
    backtracer::trace_from(backtracer::EntryPoint::new(rbp, rsp, rip), |frame| {
        count += 1;
        backtrace_format(context.as_ref(), relocated_offset, count, frame)
    });
}

#[inline(always)]
pub fn backtrace() {
    sprintln!("Backtrace:");

    let kernel_info = kcb::try_get_kcb().map(|k| {
        (
            k.kernel_binary(),
            k.kernel_args().kernel_elf_offset.as_u64(),
        )
    });
    let (elf_data, relocated_offset) = kernel_info.expect("Don't have kernel info.");
    let elf_binary =
        elfloader::ElfBinary::new("kernel", &elf_data).expect("Can't parse kernel binary.");
    let context = new_ctxt(&elf_binary);

    let mut count = 0;
    backtracer::trace(|frame| {
        count += 1;
        backtrace_format(context.as_ref(), relocated_offset, count, frame)
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
