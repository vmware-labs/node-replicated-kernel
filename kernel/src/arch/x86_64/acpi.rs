#![allow(bad_style, dead_code, unused_variables)]

use core::alloc::Layout;
use core::ffi::VaList;
use core::mem;
use core::ptr;

use super::memory::{paddr_to_kernel_vaddr, PAddr};
use crate::alloc::alloc;
use crate::alloc::vec::Vec;
use acpica_sys::*;
use cstr_core::CStr;
use log::{error, trace};

use x86::io;

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
    let mut root_ptr: ACPI_PHYSICAL_ADDRESS = 0x0;
    let ret = unsafe { AcpiFindRootPointer(&mut root_ptr) };
    if ret == AE_OK {
        root_ptr
    } else {
        0
    }
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsPredefinedOverride(
    init: *const ACPI_PREDEFINED_NAMES,
    new: *mut ACPI_STRING,
) -> ACPI_STATUS {
    trace!("AcpiOsPredefinedOverride");
    if new.is_null() {
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
    trace!("AcpiOsTableOverride");
    assert!(!new_table.is_null(), "ACPI invalid parameter supplied");
    unsafe { *new_table = ptr::null_mut() };
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsPhysicalTableOverride(
    existing_table: *mut ACPI_TABLE_HEADER,
    new_address: *mut ACPI_PHYSICAL_ADDRESS,
    new_table_len: *mut UINT32,
) -> ACPI_STATUS {
    trace!("AcpiOsPhysicalTableOverride");
    assert!(!new_address.is_null());
    assert!(!new_table_len.is_null());
    unsafe {
        *new_address = 0x0;
    }
    AE_OK
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
    trace!("AcpiOsAcquireLock");
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsReleaseLock(Handle: *mut c_void, Flags: ACPI_SIZE) {
    trace!("AcpiOsReleaseLock");
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

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsAllocate(len: ACPI_SIZE) -> *mut u8 {
    alloc::alloc(Layout::from_size_align_unchecked(len as usize, 1))
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsFree(ptr: *mut u8) {
    //alloc::dealloc(ptr, Layout::from_size_align_unchecked(len, 1));
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsMapMemory(location: ACPI_PHYSICAL_ADDRESS, len: ACPI_SIZE) -> *mut c_void {
    trace!("AcpiOsMapMemory(loc = {:#x}, len = {})", location, len);
    let p = PAddr::from_u64(location as u64);
    let vaddr = paddr_to_kernel_vaddr(p);
    vaddr.as_mut_ptr::<c_void>()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsUnmapMemory(vptr: *mut c_void, len: ACPI_SIZE) {
    trace!("AcpiOsUnmapMemory(loc = {:p}, len = {})", vptr, len);
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsGetPhysicalAddress(
    LogicalAddress: *mut c_void,
    PhysicalAddress: *mut ACPI_PHYSICAL_ADDRESS,
) -> ACPI_STATUS {
    unreachable!()
}

// These shouldn't be needed, ACPICA is compiled with its internal caching mechanism

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsInstallInterruptHandler(
    num: UINT32,
    handler: ACPI_OSD_HANDLER,
    ctxt: *mut c_void,
) -> ACPI_STATUS {
    //unreachable!()
    if handler.is_none() {
        return AE_BAD_PARAMETER;
    }

    trace!(
        "AcpiOsInstallInterruptHandler {} {:?} {:p}",
        num,
        handler,
        ctxt
    );
    AE_OK
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsRemoveInterruptHandler(
    InterruptNumber: UINT32,
    ServiceRoutine: ACPI_OSD_HANDLER,
) -> ACPI_STATUS {
    unreachable!()
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
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsWaitEventsComplete() {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsSleep(Milliseconds: UINT64) {
    unreachable!()
}

#[no_mangle]
#[linkage = "external"]
pub extern "C" fn AcpiOsStall(Microseconds: UINT32) {
    unreachable!()
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
            *value = io::inb(port) as i32;
            AE_OK
        }
        16 => {
            *value = io::inw(port) as i32;
            AE_OK
        }
        32 => {
            *value = io::inl(port) as i32;
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
pub extern "C" fn AcpiOsReadPciConfiguration(
    PciId: *mut ACPI_PCI_ID,
    Reg: UINT32,
    Value: *mut UINT64,
    Width: UINT32,
) -> ACPI_STATUS {
    unreachable!()
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

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsVprintf(format: *const i8, Args: va_list) {
    let fmt = CStr::from_ptr(format).to_str().unwrap_or("");
    error!("AcpiOsVprintf {}", fmt);
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsPrintf(format: *const i8, mut args: ...) {
    trace!("AcpiOsPrintf");
    let fmt = CStr::from_ptr(format).to_str().unwrap_or("");
    error!(" AcpiOsPrintf {}", fmt);
    //let arg1 = args.arg::<*const i8>();
    //let arg1_str = CStr::from_ptr(arg1).to_str().unwrap_or("unknown");
    //error!(" AcpiOsPrintf {}", arg1_str);

    /*let mut sum = 0;
    for _ in 0..n {
        sum += args.arg::<usize>();
    }
    sum*/
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
        let ret = AcpiInitializeSubsystem();
        assert_eq!(ret, AE_OK);
        info!("AcpiInitializeSubsystem {:?}\n", ret);

        let ret = AcpiInitializeTables(ptr::null_mut(), 16, false);
        assert_eq!(ret, AE_OK);
        info!("AcpiInitializeTables {:?}\n", ret);

        let full_init = 0x0;
        let ret = AcpiEnableSubsystem(full_init);
        assert_eq!(ret, AE_OK);
        info!("AcpiEnableSubsystem {:?}\n", ret);

        let ret = AcpiLoadTables();
        assert_eq!(ret, AE_OK);
        info!("AcpiLoadTables {:?}\n", ret);

        let ret = AcpiInitializeObjects(full_init);
        assert_eq!(ret, AE_OK);
        info!("AcpiInitializeObjects {:?}\n", ret);
    }

    Ok(())
}

pub(crate) fn process_madt() -> Result<(), ACPI_STATUS> {
    unsafe {
        let madt_handle = CStr::from_bytes_with_nul_unchecked(b"APIC\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            madt_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        assert_eq!(ret, AE_OK);

        let madt_tbl_ptr = table_header as *const ACPI_TABLE_MADT;
        let madt_table_len = (*madt_tbl_ptr).Header.Length as usize;
        let madt_table_end = (madt_tbl_ptr as *const c_void).add(madt_table_len);

        info!(
            "MADT Table: Rev={} Len={} OemID={:?}",
            (*madt_tbl_ptr).Header.Revision,
            madt_table_len,
            (*madt_tbl_ptr).Header.OemId
        );
        let mut cores = Vec::with_capacity(4);

        let mut iterator = (madt_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_MADT>());
        while iterator < madt_table_end {
            let mut entry: *const ACPI_SUBTABLE_HEADER = iterator as *const ACPI_SUBTABLE_HEADER;
            use acpica_sys::Enum_AcpiMadtType::ACPI_MADT_TYPE_LOCAL_APIC;
            let entry_type: Enum_AcpiMadtType = mem::transmute((*entry).Type as i32);

            match entry_type {
                Enum_AcpiMadtType::ACPI_MADT_TYPE_LOCAL_APIC => {
                    let ACPI_MADT_ENABLED = 0x1;
                    let local_apic: *const ACPI_MADT_LOCAL_APIC =
                        entry as *const ACPI_MADT_LOCAL_APIC;
                    let enabled: bool = (*local_apic).LapicFlags & ACPI_MADT_ENABLED > 0;
                    if enabled {
                        cores.push((
                            (*local_apic).ProcessorId,
                            (*local_apic).Id,
                            (*local_apic).LapicFlags,
                        ));
                    }
                }
                _ => debug!("Unhandled entry {:?}", entry_type),
            }

            assert!((*entry).Length > 0);
            iterator = iterator.add((*entry).Length as usize);
        }

        info!("Found cores {:?}", cores);
        assert_eq!(cores.len(), 2);
    }

    Ok(())
}
