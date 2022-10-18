// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Very basic ACPI integration -- enough to parse topology etc.

#![allow(bad_style, dead_code, unused_variables)]

use alloc::alloc;
use core::alloc::Layout;
use core::ffi::VaList;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use cstr_core::CStr;
use klogger::sprint;
use libacpica::*;
use log::{debug, error, info, trace};
use x86::io;

use super::memory::{paddr_to_kernel_vaddr, PAddr};
use crate::memory::vspace::MapAction;

const ACPI_FULL_PATHNAME: u32 = 0;
const ACPI_TYPE_INTEGER: u32 = 0x01;

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsInitialize() -> ACPI_STATUS {
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsTerminate() -> ACPI_STATUS {
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetRootPointer() -> ACPI_PHYSICAL_ADDRESS {
    let root_ptr: ACPI_PHYSICAL_ADDRESS = 0x0;

    let (rsdp1_root, rsdp2_root) = crate::KERNEL_ARGS.get().map_or((None, None), |args| {
        (Some(args.acpi1_rsdp), Some(args.acpi2_rsdp))
    });

    trace!("rsdp1 {:?} rsdp2: {:?}", rsdp1_root, rsdp2_root);
    let ptr = match (rsdp2_root, rsdp1_root) {
        (Some(ptr), _) => ptr,
        (None, Some(ptr)) => ptr,
        (None, None) => return 0,
    };

    ptr.as_u64() as ACPI_PHYSICAL_ADDRESS
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsPredefinedOverride(
    init: *const ACPI_PREDEFINED_NAMES,
    new: *mut ACPI_STRING,
) -> ACPI_STATUS {
    let name = unsafe { CStr::from_ptr((*init).Name).to_str().unwrap_or("") };
    trace!("AcpiOsPredefinedOverride {}", name);

    if new.is_null() || init.is_null() {
        AE_BAD_PARAMETER
    } else {
        unsafe {
            *new = ptr::null_mut();
        }
        AE_OK
    }
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsTableOverride(
    existing_table: *mut ACPI_TABLE_HEADER,
    new_table: *mut *mut ACPI_TABLE_HEADER,
) -> ACPI_STATUS {
    trace!("AcpiOsTableOverride {:p} {:p}", existing_table, new_table);
    if new_table.is_null() || existing_table.is_null() {
        return AE_BAD_PARAMETER;
    }

    unsafe {
        *new_table = ptr::null_mut();
    }

    AE_NO_ACPI_TABLES
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsPhysicalTableOverride(
    existing_table: *mut ACPI_TABLE_HEADER,
    new_address: *mut ACPI_PHYSICAL_ADDRESS,
    new_table_len: *mut UINT32,
) -> ACPI_STATUS {
    trace!("AcpiOsPhysicalTableOverride");
    AE_SUPPORT
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsCreateLock(OutHandle: *mut *mut c_void) -> ACPI_STATUS {
    trace!("AcpiOsCreateLock");
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsDeleteLock(Handle: *mut c_void) {
    trace!("AcpiOsDeleteLock");
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsAcquireLock(Handle: *mut c_void) -> ACPI_STATUS {
    //trace!("AcpiOsAcquireLock");
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsReleaseLock(Handle: *mut c_void, Flags: ACPI_SIZE) {
    //trace!("AcpiOsReleaseLock");
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsCreateSemaphore(
    MaxUnits: UINT32,
    InitialUnits: UINT32,
    OutHandle: *mut *mut c_void,
) -> ACPI_STATUS {
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsDeleteSemaphore(Handle: *mut c_void) -> ACPI_STATUS {
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWaitSemaphore(
    Handle: *mut c_void,
    Units: UINT32,
    Timeout: UINT16,
) -> ACPI_STATUS {
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsSignalSemaphore(Handle: *mut c_void, Units: UINT32) -> ACPI_STATUS {
    AE_OK
}

pub(crate) const HEADER_SIZE: usize = 16;

/// Implementes malloc using the `alloc::alloc` interface.
///
/// We need to add a header to store the size for the
/// `free` implementation.
#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsAllocate(size: ACPI_SIZE) -> *mut u8 {
    let size: usize = size as usize;
    trace!("AcpiOsAllocate {}", size);

    let allocation_size: u64 = (size + HEADER_SIZE) as u64;
    let alignment = 8;

    let ptr = alloc::alloc(Layout::from_size_align_unchecked(
        allocation_size as usize,
        alignment,
    ));
    if ptr != ptr::null_mut() {
        *(ptr as *mut u64) = allocation_size;
        ptr.offset(HEADER_SIZE as isize)
    } else {
        error!("Could not allocate {} bytes.", size);
        core::ptr::null_mut()
    }
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsFree(ptr: *mut u8) {
    if ptr == core::ptr::null_mut() {
        return;
    }

    let allocation_size: u64 = *(ptr.offset(-(HEADER_SIZE as isize)) as *mut u64);
    trace!("AcpiOsFree ptr {:p} size={}", ptr, allocation_size);
    alloc::dealloc(
        ptr.offset(-(HEADER_SIZE as isize)),
        Layout::from_size_align_unchecked(allocation_size as usize, 8),
    );
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsMapMemory(location: ACPI_PHYSICAL_ADDRESS, len: ACPI_SIZE) -> *mut c_void {
    trace!("AcpiOsMapMemory(loc = {:#x}, len = {})", location, len);

    let p = PAddr::from(location);
    let adjusted_len = (p - p.align_down_to_base_page().as_usize()) + len;

    use crate::round_up;
    let mut vspace = super::vspace::INITIAL_VSPACE.lock();
    vspace
        .map_identity_with_offset(
            PAddr::from(super::memory::KERNEL_BASE),
            p.align_down_to_base_page(),
            round_up!(adjusted_len.as_usize(), x86::bits64::paging::BASE_PAGE_SIZE),
            MapAction::kernel() | MapAction::write(),
        )
        .expect("Can't map ACPI memory");

    let vaddr = paddr_to_kernel_vaddr(p);
    vaddr.as_mut_ptr::<c_void>()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsUnmapMemory(vptr: *mut c_void, len: ACPI_SIZE) {
    debug!("AcpiOsUnmapMemory(loc = {:p}, len = {})", vptr, len);
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetPhysicalAddress(
    LogicalAddress: *mut c_void,
    PhysicalAddress: *mut ACPI_PHYSICAL_ADDRESS,
) -> ACPI_STATUS {
    unreachable!("AcpiOsGetPhysicalAddress")
}

// These shouldn't be needed, ACPICA is compiled with its internal caching mechanism

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsInstallInterruptHandler(
    num: UINT32,
    handler: ACPI_OSD_HANDLER,
    ctxt: *mut c_void,
) -> ACPI_STATUS {
    if handler.is_none() {
        return AE_BAD_PARAMETER;
    }

    debug!(
        "AcpiOsInstallInterruptHandler {} {:?} {:p}",
        num, handler, ctxt
    );
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsRemoveInterruptHandler(
    InterruptNumber: UINT32,
    ServiceRoutine: ACPI_OSD_HANDLER,
) -> ACPI_STATUS {
    unreachable!("AcpiOsRemoveInterruptHandler")
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetThreadId() -> UINT64 {
    1
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsExecute(
    Type: ACPI_EXECUTE_TYPE,
    Function: ACPI_OSD_EXEC_CALLBACK,
    Context: *mut c_void,
) -> ACPI_STATUS {
    unreachable!("AcpiOsExecute")
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWaitEventsComplete() {
    unreachable!("AcpiOsWaitEventsComplete")
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsSleep(Milliseconds: UINT64) {
    unreachable!("AcpiOsSleep")
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsStall(Microseconds: UINT32) {
    unreachable!("AcpiOsStall")
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsReadPort(
    address: ACPI_IO_ADDRESS,
    value: *mut UINT32,
    width: UINT32,
) -> ACPI_STATUS {
    let port = address as u16;
    match width {
        8 => {
            *value = io::inb(port) as u32;
            AE_OK
        }
        16 => {
            *value = io::inw(port) as u32;
            AE_OK
        }
        32 => {
            *value = io::inl(port) as u32;
            AE_OK
        }
        _ => AE_BAD_PARAMETER,
    }
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsWritePort(
    address: ACPI_IO_ADDRESS,
    val: UINT32,
    width: UINT32,
) -> ACPI_STATUS {
    let port = address as u16;
    match width {
        8 => {
            io::outb(port, val as u8);
            AE_OK
        }
        16 => {
            io::outw(port, val as u16);
            AE_OK
        }
        32 => {
            io::outl(port, val as u32);
            AE_OK
        }
        _ => AE_BAD_PARAMETER,
    }
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsReadMemory(
    Address: ACPI_PHYSICAL_ADDRESS,
    Value: *mut UINT64,
    Width: UINT32,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWriteMemory(
    Address: ACPI_PHYSICAL_ADDRESS,
    Value: UINT64,
    Width: UINT32,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsReadPciConfiguration(
    pci_id: *mut ACPI_PCI_ID,
    reg: UINT32,
    value: *mut UINT64,
    width: UINT32,
) -> ACPI_STATUS {
    static PCI_CONF_ADDR: u16 = 0xcf8;
    static PCI_CONF_DATA: u16 = 0xcfc;

    let (bus, dev, fun) = (
        (*pci_id).Bus.into(),
        (*pci_id).Device.into(),
        (*pci_id).Function.into(),
    );
    trace!(
        "AcpiOsReadPciConfiguration {}:{}:{} {} {:p} {}",
        bus,
        dev,
        fun,
        reg,
        value,
        width
    );

    fn pci_bus_address(bus: u32, dev: u32, fun: u32, reg: i32) -> u32 {
        assert!(reg <= 0xfc);
        (1 << 31) | (bus << 16) | (dev << 11) | (fun << 8) | (reg as u32 & 0xfc)
    }

    let addr = pci_bus_address(bus, dev, fun, reg as i32);

    match width {
        8 => {
            io::outl(PCI_CONF_ADDR, addr);
            *value = io::inb(PCI_CONF_DATA).into();
            AE_OK
        }
        16 => {
            io::outl(PCI_CONF_ADDR, addr);
            *value = io::inw(PCI_CONF_DATA).into();
            AE_OK
        }
        32 => {
            io::outl(PCI_CONF_ADDR, addr);
            *value = io::inl(PCI_CONF_DATA).into();
            AE_OK
        }
        _ => AE_BAD_PARAMETER,
    }
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWritePciConfiguration(
    PciId: *mut ACPI_PCI_ID,
    Reg: UINT32,
    Value: UINT64,
    Width: UINT32,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsReadable(Pointer: *mut c_void, Length: ACPI_SIZE) -> BOOLEAN {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWritable(Pointer: *mut c_void, Length: ACPI_SIZE) -> BOOLEAN {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetTimer() -> UINT64 {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsSignal(Function: UINT32, Info: *mut c_void) -> ACPI_STATUS {
    unreachable!()
}

// Define the printf function in `acpi_printf.c`
// The alternative to using this approach is to write our own
// C printf function in rust if we want to make sense of ACPI
// debug messages (I don't want to do that...)
extern "C" {
    fn vprintf_(format: *const i8, args: VaList);
    fn printf_(fmt: *const i8, ...) -> i32;
}

/// Needed for the C-based printf implementations.
#[no_mangle]
pub extern "C" fn _putchar(c: u8) {
    sprint!("{}", c as char);
}

/// Should we do printing in `AcpiOsVprintf`?
///
/// Note this is a global variable because otherwise the linker is too smart and
/// realizes we never use `vprintf_` and the other stuff in nrk_asm, which means
/// it won't make it way into the binary (and since the acpica library also
/// relies on these functions, it complains with `fwrite` not found).
static TOGGLE_PRINT: AtomicBool = AtomicBool::new(false);

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsVprintf(format: *const i8, args: VaList) {
    if TOGGLE_PRINT.load(Ordering::Relaxed) {
        vprintf_(format, args);
    }
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsPrintf(format: *const i8, args: ...) {
    // Unfortunately the printf() implementation can crash the
    // ACPI initialization on bare-metal sometimes, so currently
    // printf_ is disabled...
    //printf_(format, args);
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsRedirectOutput(Destination: *mut c_void) {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetLine(
    Buffer: *mut i8,
    BufferLength: UINT32,
    BytesRead: *mut UINT32,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetTableByName(
    Signature: *mut i8,
    Instance: UINT32,
    Table: *mut *mut ACPI_TABLE_HEADER,
    Address: *mut ACPI_PHYSICAL_ADDRESS,
) -> ACPI_STATUS {
    AE_SUPPORT
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetTableByIndex(
    Index: UINT32,
    Table: *mut *mut ACPI_TABLE_HEADER,
    Instance: *mut UINT32,
    Address: *mut ACPI_PHYSICAL_ADDRESS,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetTableByAddress(
    Address: ACPI_PHYSICAL_ADDRESS,
    Table: *mut *mut ACPI_TABLE_HEADER,
) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsOpenDirectory(
    Pathname: *mut i8,
    WildcardSpec: *mut i8,
    RequestedFileType: i8,
) -> *mut c_void {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetNextFilename(DirHandle: *mut c_void) -> *mut i8 {
    // Intentionally unsupported
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsCloseDirectory(DirHandle: *mut c_void) {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsOpenFile(Path: *const i8, Modes: UINT8) -> *mut c_void {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsCloseFile(File: *mut c_void) {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsReadFile(
    File: *mut c_void,
    Buffer: *mut c_void,
    Size: ACPI_SIZE,
    Count: ACPI_SIZE,
) -> i32 {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWriteFile(
    File: *mut c_void,
    Buffer: *mut c_void,
    Size: ACPI_SIZE,
    Count: ACPI_SIZE,
) -> i32 {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetFileOffset(File: *mut c_void) -> i32 {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsSetFileOffset(File: *mut c_void, Offset: i32, From: UINT8) -> ACPI_STATUS {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsTracePoint(
    Type: ACPI_TRACE_EVENT_TYPE,
    Begin: BOOLEAN,
    Aml: *mut UINT8,
    Pathname: *mut i8,
) {
    unreachable!()
}

pub(crate) fn init() -> Result<(), ACPI_STATUS> {
    unsafe {
        /*
        // For more debug info from ACPI:

        #[linkage = "external"]
        extern "C" {
            #[no_mangle]
            static mut AcpiDbgLevel: u32;
            #[no_mangle]
            static mut AcpiDbgLayer: u32;
        }
        AcpiDbgLayer = 0x00000400;
        AcpiDbgLevel = 0x000FFF40;
        */

        let ret = AcpiInitializeSubsystem();
        assert_eq!(ret, AE_OK);
        trace!("AcpiInitializeSubsystem {:?}", ret);

        let ret = AcpiInitializeTables(ptr::null_mut(), 16, false);
        assert_eq!(ret, AE_OK);
        trace!("AcpiInitializeTables {:?}", ret);

        let full_init = 0x0;
        let ret = AcpiEnableSubsystem(full_init);
        assert_eq!(ret, AE_OK);
        trace!("AcpiEnableSubsystem {:?}", ret);

        let ret = AcpiLoadTables();
        assert_eq!(ret, AE_OK);
        trace!("AcpiLoadTables {:?}", ret);

        let ret = AcpiInitializeObjects(full_init);
        assert_eq!(ret, AE_OK);
        //trace!("AcpiInitializeObjects {:?}", ret);
    }

    // Required for integration test, don't modify without adjusting
    // `acpi_topology` test
    info!("ACPI Initialized");

    // Set this to true in case ACPI wants to tell us something (probably important because we already initialized)
    // in the future:
    TOGGLE_PRINT.store(true, Ordering::Relaxed);

    Ok(())
}
