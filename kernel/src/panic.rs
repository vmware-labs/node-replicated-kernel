// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(target_os = "none")]
use core::alloc::Layout;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
use crate::arch;
use crate::kcb;
#[cfg(target_os = "none")]
use crate::ExitReason;
use addr2line::{gimli, Context};
use alloc::rc::Rc;
use klogger::{sprint, sprintln};

//pub type EndianRcSlice<gimli::Endian> = gimli::EndianReader<gimli::Endian, Rc<[u8]>>;

fn new_ctxt(
    file: &elfloader::ElfBinary,
) -> Option<Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>> {
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
    let debug_aranges: gimli::DebugAranges<_> = load_section(file, endian);
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
        debug_aranges,
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
    context: Option<&Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>>,
    relocated_offset: u64,
    count: usize,
    frame: &backtracer_core::Frame,
) -> bool {
    let ip = frame.ip();
    sprint!("frame #{:<2} - {:#02$x}", count, ip as usize, 20);
    let mut resolved = false;

    let _r = backtracer_core::resolve(context, relocated_offset, ip, |symbol| {
        if !resolved {
            resolved = true;
        } else {
            sprint!("                                ");
        }
        if let Some(name) = symbol.name() {
            if name.as_bytes().is_empty() {
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
    let kernel_info = kcb::try_get_kcb().map(|k| {
        (
            k.kernel_binary(),
            k.arch.kernel_args().kernel_elf_offset.as_u64(),
        )
    });

    if kernel_info.is_some() {
        sprintln!("Backtrace:");
        let (elf_data, relocated_offset) = kernel_info.expect("Don't have kernel info");
        match elfloader::ElfBinary::new(elf_data) {
            Ok(elf_binary) => {
                let context = new_ctxt(&elf_binary);

                let mut count = 0;
                backtracer_core::trace_from(
                    backtracer_core::EntryPoint::new(rbp, rsp, rip),
                    |frame| {
                        count += 1;
                        backtrace_format(context.as_ref(), relocated_offset, count, frame)
                    },
                );
                // TODO(bug): Investigate why freeing context tries to dealloc an invalid
                // (not alloc'd) pointer... Not critical since we're panicking already.
                core::mem::forget(context);
            }
            Err(e) => {
                sprintln!("Backtrace unavailable (can't parse kernel binary: '{}')", e);
            }
        }
    } else {
        sprintln!("Backtrace unavailable (binary information missing)");
    }
}

#[inline(always)]
pub fn backtrace() {
    let kernel_info = kcb::try_get_kcb().map(|k| {
        (
            k.kernel_binary(),
            k.arch.kernel_args().kernel_elf_offset.as_u64(),
        )
    });

    if kernel_info.is_some() {
        sprintln!("Backtrace:");

        let (elf_data, relocated_offset) = kernel_info.expect("Don't have kernel info.");
        match elfloader::ElfBinary::new(elf_data) {
            Ok(elf_binary) => {
                let context = new_ctxt(&elf_binary);
                let mut count = 0;
                backtracer_core::trace(|frame| {
                    count += 1;
                    backtrace_format(context.as_ref(), relocated_offset, count, frame)
                });
            }
            Err(e) => {
                sprintln!("Backtrace unavailable (can't parse kernel binary: '{}')", e);
            }
        }
    } else {
        sprintln!("Backtrace unavailable (binary information missing)");
    }
}

#[allow(unused)]
#[inline(always)]
pub fn backtrace_no_context() {
    sprintln!("Backtrace:");
    let relocation_offset =
        kcb::try_get_kcb().map_or(0x0, |k| k.arch.kernel_args().kernel_elf_offset.as_u64());

    let mut count = 0;
    backtracer_core::trace(|frame| {
        count += 1;
        backtrace_format(None, relocation_offset, count, frame)
    });
}

#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", panic_handler)]
#[no_mangle]
pub fn panic_impl(info: &PanicInfo) -> ! {
    sprint!(
        "System panic encountered (On H/W thread {})",
        atopology::MACHINE_TOPOLOGY.current_thread().id
    );

    if let Some(message) = info.message() {
        sprint!(": '{}'", message);
    }
    if let Some(location) = info.location() {
        sprintln!(" in {}:{}", location.file(), location.line());
    } else {
        sprintln!("");
    }

    // We need memory allocation for a backtrace, can't do that without a KCB
    kcb::try_get_kcb().map(|k| {
        // If we're already panicking, it usually doesn't help to panic more
        if !k.in_panic_mode {
            // Make sure we use the e{early, emergency} memory allocator for backtracing
            // (if we have a panic with the memory manager already borrowed
            // we can't use it because it will just trigger another panic)
            k.set_panic_mode();
            backtrace();
        } else {
            sprintln!("Encountered a recursive panic, exit immediately!")
        }
    });

    arch::debug::shutdown(ExitReason::KernelPanic);
}

#[cfg(target_os = "none")]
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

#[cfg(target_os = "none")]
#[allow(non_camel_case_types)]
pub struct _Unwind_Context;

#[cfg(target_os = "none")]
#[allow(non_camel_case_types)]
pub type _Unwind_Action = u32;

#[cfg(target_os = "none")]
static _UA_SEARCH_PHASE: _Unwind_Action = 1;

#[cfg(target_os = "none")]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct _Unwind_Exception {
    exception_class: u64,
    exception_cleanup: fn(_Unwind_Reason_Code, *const _Unwind_Exception),
    private: [u64; 2],
}

#[cfg(target_os = "none")]
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

#[cfg(target_os = "none")]
#[no_mangle]
#[cfg_attr(target_os = "none", lang = "oom")]
pub fn oom(layout: Layout) -> ! {
    sprintln!(
        "OOM: Unable to satisfy allocation request for size {} with alignment {}.",
        layout.size(),
        layout.align()
    );
    backtrace_no_context();

    // Not worth initiating a backtrace as it would require memory.
    // TODO: fall back to a backtrace function without allocations here.
    arch::debug::shutdown(ExitReason::OutOfMemory);
}

#[cfg(target_os = "none")]
#[no_mangle]
#[allow(non_snake_case)]
pub fn _Unwind_Resume() {
    loop {}
}
