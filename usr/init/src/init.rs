#![no_std]
#![no_main]
#![feature(alloc_error_handler, const_fn, panic_info_message)]

extern crate alloc;
extern crate spin;

extern crate lineup;

use alloc::format;
use alloc::vec::Vec;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::transmute;
use core::panic::PanicInfo;
use core::ptr;
use core::slice::from_raw_parts_mut;

use vibrio::sys_println;

use log::{debug, error, info};
use log::{Level, Metadata, Record, SetLoggerError};

#[global_allocator]
static MEM_PROVIDER: vibrio::mem::SafeZoneAllocator =
    vibrio::mem::SafeZoneAllocator::new(&vibrio::mem::PAGER);

fn print_test() {
    vibrio::print("test\r\n");
    info!("log test");
}

fn map_test() {
    let base: u64 = 0xff000;
    let size: u64 = 0x1000 * 64;
    vibrio::vspace(vibrio::VSpaceOperation::Map, base, size);
    unsafe {
        let mut slice: &mut [u8] = from_raw_parts_mut(base as *mut u8, size as usize);
        for i in slice.iter_mut() {
            *i = 0xb;
        }
        assert_eq!(slice[99], 0xb);
    }
}

fn alloc_test() {
    use alloc::vec::Vec;
    let mut v: Vec<u16> = Vec::with_capacity(256);

    for e in 0..256 {
        v.push(e);
    }

    assert_eq!(v[255], 255);
    assert_eq!(v.len(), 256);
}

fn scheduler_test() {
    vibrio::print("scheduler test");
    use lineup::DEFAULT_UPCALLS;
    let mut s = lineup::Scheduler::new(DEFAULT_UPCALLS);

    s.spawn(
        32 * 4096,
        move |_| {
            info!("weee from t1");
        },
        ptr::null_mut(),
    );

    s.spawn(
        32 * 4096,
        move |_| {
            info!("weee from t2");
        },
        ptr::null_mut(),
    );

    s.run();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        log::set_logger(&vibrio::writer::LOGGER)
            .map(|()| log::set_max_level(Level::Debug.to_level_filter()));
    }
    debug!("INIT LOGGING");

    print_test();
    map_test();
    alloc_test();
    scheduler_test();

    debug!("DONE WITH INIT");

    vibrio::exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("panic happened: {:?}", info.message());
    vibrio::exit(1);
    loop {}
}

#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("oom {:?}", layout)
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
#[allow(non_snake_case)]
pub fn _Unwind_Resume() {
    loop {}
}
