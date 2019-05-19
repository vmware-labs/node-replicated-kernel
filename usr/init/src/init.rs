#![no_std]
#![no_main]
#![feature(alloc_error_handler, const_fn)]

extern crate alloc;
extern crate rlibc;
extern crate slabmalloc;
extern crate spin;

use alloc::format;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::transmute;
use core::panic::PanicInfo;
use core::slice::from_raw_parts_mut;

use kpi;

use slabmalloc::{ObjectPage, PageProvider, ZoneAllocator};
use spin::Mutex;

struct Pager(u64);

impl<'a> PageProvider<'a> for Pager {
    fn allocate_page(&mut self) -> Option<&'a mut ObjectPage<'a>> {
        let r = kpi::vspace(kpi::VSpaceOperation::Map, self.0, 0x1000);
        let sp: &'a mut ObjectPage = unsafe { transmute(self.0) };

        self.0 += 0x1000;

        Some(sp)
    }

    fn release_page(&mut self, page: &'a mut ObjectPage<'a>) {}
}

static PAGER: Mutex<Pager> = Mutex::new(Pager(0xabfff000));
#[global_allocator]
static MEM_PROVIDER: SafeZoneAllocator = SafeZoneAllocator::new(&PAGER);

pub struct SafeZoneAllocator(Mutex<ZoneAllocator<'static>>);

impl SafeZoneAllocator {
    pub const fn new(provider: &'static Mutex<PageProvider>) -> SafeZoneAllocator {
        SafeZoneAllocator(Mutex::new(ZoneAllocator::new(provider)))
    }
}

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            self.0.lock().allocate(layout)
        } else {
            panic!("NYI");
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() <= ZoneAllocator::MAX_ALLOC_SIZE {
            self.0.lock().deallocate(ptr, layout);
        } else {
            panic!("NYI");
        }
    }
}

fn print_test() {
    kpi::print("test");
}

fn map_test() {
    let base: u64 = 0xff000;
    let size: u64 = 0x1000 * 64;
    kpi::vspace(kpi::VSpaceOperation::Map, base, size);
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

    assert_eq!(v[1023], 1023);
    assert_eq!(v.len(), 256);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    print_test();
    map_test();
    alloc_test();

    kpi::exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    //kpi::print(format!("panic: {:?}", info.location()).as_str());
    kpi::exit(1);
    loop {}
}

#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! {
    panic!("oom")
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
