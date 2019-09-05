#![allow(bad_style, dead_code, unused_variables)]

use core::alloc::Layout;
use core::ffi::VaList;
use core::fmt;
use core::mem;
use core::ptr;

use super::memory::{paddr_to_kernel_vaddr, PAddr};
use crate::alloc::alloc;
use crate::alloc::vec::Vec;
use acpica_sys::*;
use cstr_core::CStr;
use log::{error, trace};

use super::vspace::{MapAction, VSpace};

use x86::io;

// TODO: We shouldn't have to call process_madt twice!
lazy_static! {
    /// A list of cores available in the system.
    ///
    /// This should probably not be here since we want to handle
    /// hotplug eventually.
    pub static ref LOCAL_APICS: Vec<LocalApic> = {
        let (cores, _) = process_madt();
        cores
    };

    /// A list of I/O APICs in the system.
    ///
    /// Ideally we get rid of I/O APIC entirely and just use MSI.
    pub static ref IO_APICS: Vec<IoApic> = {
        let (_, ioapics) = process_madt();
        ioapics
    };

}

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

    let (rsdp1_root, rsdp2_root) = crate::kcb::try_get_kcb().map_or((None, None), |k| {
        let args = k.kernel_args();
        (Some(args.acpi1_rsdp), Some(args.acpi2_rsdp))
    });

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

    let p = PAddr::from((location & !0xfff) as u64);

    use crate::round_up;
    crate::kcb::try_get_kcb().map(|k| {
        let mut vspace = k.init_vspace();
        vspace.map_identity_with_offset(
            PAddr::from(super::memory::KERNEL_BASE),
            p,
            PAddr::from(round_up!(
                (location + len) as usize,
                x86::bits64::paging::BASE_PAGE_SIZE
            ) as u64),
            MapAction::ReadWriteKernel,
        );
    });

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
pub unsafe extern "C" fn AcpiOsVprintf(format: *const i8, Args: VaList) {
    let fmt = CStr::from_ptr(format).to_str().unwrap_or("");
    debug!("AcpiOsVprintf {}", fmt);
}

#[no_mangle]
#[linkage = "external"]
pub unsafe extern "C" fn AcpiOsPrintf(format: *const i8, args: ...) {
    trace!("AcpiOsPrintf");
    let fmt = CStr::from_ptr(format).to_str().unwrap_or("");
    debug!("AcpiOsPrintf {}", fmt);
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
        trace!("AcpiInitializeObjects {:?}", ret);
    }

    info!("ACPI Initialized");

    Ok(())
}

#[derive(Eq, PartialEq)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub global_irq_base: u32,
}

impl fmt::Debug for IoApic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Hex(u32);
        impl fmt::Debug for Hex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }
        let mut s = f.debug_struct("IoApic");
        s.field("id", &self.id);
        s.field("address", &Hex(self.address));
        s.field("global_irq_base", &self.global_irq_base);

        s.finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LocalApic {
    pub processor_id: u8,
    pub core_id: u8,
    pub enabled: bool,
}

const ACPI_FULL_PATHNAME: u32 = 0;
const ACPI_TYPE_INTEGER: u32 = 0x01;

fn acpi_get_integer(handle: ACPI_HANDLE, name: *const i8, reg: &mut ACPI_INTEGER) -> ACPI_STATUS {
    unsafe {
        let mut object: ACPI_OBJECT = mem::uninitialized();
        let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
            Length: mem::size_of::<ACPI_OBJECT>() as u64,
            Pointer: &mut object as *mut _ as *mut acpica_sys::c_void,
        };

        let ret = AcpiEvaluateObjectTyped(
            handle,
            name as *mut i8,
            ptr::null_mut(),
            &mut namebuf,
            ACPI_TYPE_INTEGER,
        );

        if ret == AE_OK {
            *reg = (*object.Integer()).Value;
        }
        ret
    }
}

pub fn process_pcie() {
    unsafe {
        let pcie_exp = CStr::from_bytes_with_nul_unchecked(b"PNP0A03\0");

        unsafe extern "C" fn call_back(
            handle: ACPI_HANDLE,
            nexting: u32,
            context: *mut acpica_sys::c_void,
            return_value: *mut *mut acpica_sys::c_void,
        ) -> u32 {
            let mut namebuf: ACPI_BUFFER = ACPI_BUFFER {
                Length: 256,
                Pointer: alloc::alloc(Layout::from_size_align_unchecked(128, 0x1))
                    as *mut acpica_sys::c_void,
            };
            let ret = AcpiGetName(handle, ACPI_FULL_PATHNAME, &mut namebuf);
            let name = unsafe {
                CStr::from_ptr(namebuf.Pointer as *const i8)
                    .to_str()
                    .unwrap_or("")
            };

            let mut address: ACPI_INTEGER = 0x0;
            let adr_cstr = CStr::from_bytes_with_nul_unchecked(b"_ADR\0");
            acpi_get_integer(handle, adr_cstr.as_ptr() as *const i8, &mut address);

            let mut bus_number: ACPI_INTEGER = 0x0;
            let adr_cstr = CStr::from_bytes_with_nul_unchecked(b"_BBN\0");
            let bbn_ret = acpi_get_integer(handle, adr_cstr.as_ptr() as *const i8, &mut bus_number);

            let bus = if bbn_ret == AE_OK {
                bus_number as u16
            } else {
                0u16
            };

            let device: u16 = (address >> 16) as u16 & 0xffff;
            let function: u16 = address as u16 & 0xffff;

            info!(
                "PCIe bridge name={} bus={} device={} function={}",
                name, bus, device, function
            );

            AE_OK
        }

        let ret = AcpiGetDevices(
            pcie_exp.as_ptr() as *mut cstr_core::c_char,
            Some(call_back),
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }
}

/// Association between the APIC ID or SAPIC ID/EID of a processor
/// and the proximity domain to which the processor belongs.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalApicAffinity {
    /// Processor local APIC ID.
    pub apic_id: u8,
    /// Processor local SAPIC EID.
    pub sapic_eid: u8,
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// The clock domain to which the processor belongs to.
    pub clock_domain: u32,
    /// True if the entry refers to an enabled local APIC.
    pub enabled: bool,
}

/// The Memory Affinity structure provides the following topology information
/// statically to the operating system:
///
/// - The association between a range of memory and the proximity domain to which it belongs
/// - Information about whether the range of memory can be hot-plugged.
#[derive(Eq, PartialEq)]
pub struct MemoryAffinity {
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// Base Address of the memory range.
    pub base_address: u64,
    /// Length of the memory range.
    pub length: u64,
    /// True if the entry refers to enabled memory.
    pub enabled: bool,
    /// System hardware supports hot-add and hot-remove of this memory region.
    pub hotplug_capable: bool,
    /// The memory region represents Non-Volatile memory.
    pub non_volatile: bool,
}

impl fmt::Debug for MemoryAffinity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MemoryAffinity {{ proximity_domain: {}, base_address: {:#x}, length: {:#x} }}",
            self.proximity_domain, self.base_address, self.length
        )
    }
}

/// Processor Local x2APIC Affinity structure provides the association
/// between the local x2APIC ID of a processor and the proximity domain
/// to which the processor belongs.
#[derive(Debug, Eq, PartialEq)]
pub struct LocalX2ApicAffinity {
    /// Processor local x2APIC ID.
    pub x2apic_id: u32,
    /// Proximity domain to wich the processor belongs.
    pub proximity_domain: u32,
    /// The clock domain to which the processor belongs to.
    pub clock_domain: u32,
    /// True if the entry refers to an enabled local x2APIC.
    pub enabled: bool,
}

/// Parse the SRAT table (static resource allocation structures for the platform).
///
/// This essentially figures out the NUMA topology of your system.
///
/// Returns entries of
/// * LocalApicAffinity: to inform about which core belongs to which NUMA node.
/// * LocalX2ApicAffinity: to inform about which core belongs to which NUMA node.
/// * MemoryAffinity: to inform which memory region belongs to which NUMA node.
pub fn process_srat() -> (
    Vec<LocalApicAffinity>,
    Vec<LocalX2ApicAffinity>,
    Vec<MemoryAffinity>,
) {
    let mut apic_affinity = Vec::with_capacity(24);
    let mut x2apic_affinity = Vec::with_capacity(24);
    let mut mem_affinity = Vec::with_capacity(8);

    unsafe {
        let srat_handle = CStr::from_bytes_with_nul_unchecked(b"SRAT\0");
        let mut table_header: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let ret = AcpiGetTable(
            srat_handle.as_ptr() as *mut cstr_core::c_char,
            1,
            &mut table_header,
        );
        assert_eq!(ret, AE_OK);

        let srat_tbl_ptr = table_header as *const ACPI_TABLE_SRAT;
        let srat_table_len = (*srat_tbl_ptr).Header.Length as usize;
        let srat_table_end = (srat_tbl_ptr as *const c_void).add(srat_table_len);

        trace!(
            "SRAT Table: Rev={} Len={} OemID={:?}",
            (*srat_tbl_ptr).Header.Revision,
            srat_table_len,
            (*srat_tbl_ptr).Header.OemId
        );

        let mut iterator = (srat_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_SRAT>());
        while iterator < srat_table_end {
            let entry: *const ACPI_SUBTABLE_HEADER = iterator as *const ACPI_SUBTABLE_HEADER;
            let entry_type: Enum_AcpiSratType = mem::transmute((*entry).Type as i32);

            match entry_type {
                Enum_AcpiSratType::ACPI_SRAT_TYPE_CPU_AFFINITY => {
                    let ACPI_SRAT_ENABLED = 0x1;

                    let local_apic_affinity: *const ACPI_SRAT_CPU_AFFINITY =
                        entry as *const ACPI_SRAT_CPU_AFFINITY;

                    let apic_id = (*local_apic_affinity).ApicId;
                    let sapic_eid = (*local_apic_affinity).LocalSapicEid;
                    let proximity_domain: u32 = (*local_apic_affinity).ProximityDomainLo as u32
                        | (((*local_apic_affinity).ProximityDomainHi[0] as u32) << 8)
                        | (((*local_apic_affinity).ProximityDomainHi[1] as u32) << 16)
                        | (((*local_apic_affinity).ProximityDomainHi[2] as u32) << 24);
                    let clock_domain = (*local_apic_affinity).ClockDomain;
                    let enabled = (*local_apic_affinity).Flags & ACPI_SRAT_ENABLED > 0;

                    let parsed_entry = LocalApicAffinity {
                        apic_id,
                        sapic_eid,
                        proximity_domain,
                        clock_domain,
                        enabled,
                    };

                    error!("SRAT entry: {:?}", parsed_entry);
                    if enabled {
                        apic_affinity.push(parsed_entry);
                    }

                    debug_assert_eq!((*entry).Length, 16);
                }
                Enum_AcpiSratType::ACPI_SRAT_TYPE_MEMORY_AFFINITY => {
                    let ACPI_SRAT_ENABLED = 0x1;
                    let ACPI_SRAT_HOTPLUGGABLE = 0x1 << 1;
                    let ACPI_SRAT_NON_VOLATILE = 0x1 << 2;

                    let mem_affinity_entry: *const ACPI_SRAT_MEM_AFFINITY =
                        entry as *const ACPI_SRAT_MEM_AFFINITY;

                    let proximity_domain = (*mem_affinity_entry).ProximityDomain;
                    let base_address = (*mem_affinity_entry).BaseAddress;
                    let length = (*mem_affinity_entry).Length;
                    let enabled = (*mem_affinity_entry).Flags & ACPI_SRAT_ENABLED > 0;
                    let hotplug_capable = (*mem_affinity_entry).Flags & ACPI_SRAT_HOTPLUGGABLE > 0;
                    let non_volatile = (*mem_affinity_entry).Flags & ACPI_SRAT_NON_VOLATILE > 0;

                    let parsed_entry = MemoryAffinity {
                        proximity_domain,
                        base_address,
                        length,
                        enabled,
                        hotplug_capable,
                        non_volatile,
                    };

                    error!("SRAT entry: {:?}", parsed_entry);
                    if enabled {
                        mem_affinity.push(parsed_entry);
                    }

                    debug_assert_eq!((*entry).Length, 40);
                }
                Enum_AcpiSratType::ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY => {
                    let ACPI_SRAT_ENABLED = 0x1;

                    let x2apic_affinity_entry: *const ACPI_SRAT_X2APIC_CPU_AFFINITY =
                        entry as *const ACPI_SRAT_X2APIC_CPU_AFFINITY;

                    let x2apic_id: u32 = (*x2apic_affinity_entry).ApicId;
                    let proximity_domain: u32 = (*x2apic_affinity_entry).ProximityDomain;
                    let clock_domain: u32 = (*x2apic_affinity_entry).ClockDomain;
                    let enabled: bool = (*x2apic_affinity_entry).Flags & ACPI_SRAT_ENABLED > 0;

                    let parsed_entry = LocalX2ApicAffinity {
                        x2apic_id,
                        proximity_domain,
                        clock_domain,
                        enabled,
                    };

                    error!("SRAT entry: {:?}", parsed_entry);
                    if enabled {
                        x2apic_affinity.push(parsed_entry);
                    }

                    debug_assert_eq!((*entry).Length, 24);
                }
                _ => error!("Unhandled SRAT entry {:?}", entry_type),
            }

            assert!((*entry).Length > 0);
            iterator = iterator.add((*entry).Length as usize);
        }
    }

    (apic_affinity, x2apic_affinity, mem_affinity)
}

/// Parse the MADT table.
///
/// This will find all
///  - Local APICs (cores)
///  - IO APICs (IRQ controllers)
/// in the system, and return them.
///
/// # Note
/// Some cores may be disabled (i.e., if we disabled hyper-threading),
/// we ignore them at the moment.
fn process_madt() -> (Vec<LocalApic>, Vec<IoApic>) {
    let mut cores = Vec::with_capacity(24);
    let mut io_apics = Vec::with_capacity(24);

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

        trace!(
            "MADT Table: Rev={} Len={} OemID={:?}",
            (*madt_tbl_ptr).Header.Revision,
            madt_table_len,
            (*madt_tbl_ptr).Header.OemId
        );

        let mut iterator = (madt_tbl_ptr as *const c_void).add(mem::size_of::<ACPI_TABLE_MADT>());
        while iterator < madt_table_end {
            let entry: *const ACPI_SUBTABLE_HEADER = iterator as *const ACPI_SUBTABLE_HEADER;
            let entry_type: Enum_AcpiMadtType = mem::transmute((*entry).Type as i32);

            match entry_type {
                Enum_AcpiMadtType::ACPI_MADT_TYPE_LOCAL_APIC => {
                    let ACPI_MADT_ENABLED = 0x1;
                    let local_apic: *const ACPI_MADT_LOCAL_APIC =
                        entry as *const ACPI_MADT_LOCAL_APIC;

                    let processor_id = (*local_apic).ProcessorId;
                    let core_id = (*local_apic).Id;
                    let enabled: bool = (*local_apic).LapicFlags & ACPI_MADT_ENABLED > 0;

                    if enabled {
                        let core = LocalApic {
                            processor_id,
                            core_id,
                            enabled,
                        };
                        cores.push(core);
                    }
                }
                Enum_AcpiMadtType::ACPI_MADT_TYPE_IO_APIC => {
                    let io_apic: *const ACPI_MADT_IO_APIC = entry as *const ACPI_MADT_IO_APIC;

                    let apic = IoApic {
                        id: (*io_apic).Id,
                        address: (*io_apic).Address as u32,
                        global_irq_base: (*io_apic).GlobalIrqBase as u32,
                    };
                    io_apics.push(apic);
                }
                _ => debug!("Unhandled entry {:?}", entry_type),
            }

            assert!((*entry).Length > 0);
            iterator = iterator.add((*entry).Length as usize);
        }
    }

    (cores, io_apics)
}
