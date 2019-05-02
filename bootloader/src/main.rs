//! A UEFI based bootloader for an x86-64 kernel.
//!
//! This code roughly does the following: looks for a kernel binary
//! in the EFI partition, loads it, then continues to construct an
//! address space for it, and finally it switches to the new address
//! space and executes the kernel entry function. In addition we
//! gather a bit of information about memory regions and pass this
//! information on to the kernel.
//!
//! When the CPU driver on the boot core begins executing, the following
//! statements hold:
//!
//!  * XXX
//!

#![no_std]
#![no_main]
#![feature(alloc, asm, global_asm, slice_patterns)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

extern crate uefi;
extern crate uefi_exts;
extern crate uefi_services;

extern crate elfloader;
extern crate x86;

use core::mem;
use core::mem::transmute;
use core::slice;

use uefi::prelude::*;
use uefi::proto::media::file::*;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, BootServices, MemoryDescriptor, MemoryMapIter, MemoryType};
use uefi::table::Runtime;

use crate::alloc::vec::Vec;

use x86::bits64::paging::*;

use x86::controlregs;

mod boot;
mod setup;

use setup::*;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}


#[repr(C, packed)]
pub struct KernelArgs {
    /// An iterator over the UEFI memory map (which is also mapped in memory).
    pub mm: MemoryMapIter<'static>,
    /// The physical address of the kernel address space that gets loaded in cr3.
    pub pml4: PAddr,
    /// Mapping of the kernel stack base address.
    pub stack_base: (VAddr, PAddr),
    /// Mapping location of the loaded kernel binary file.
    pub kernel_binary: (VAddr, PAddr),
}

// Include the `jump_to_kernel` assembly function. This does some things we can't express in
// rust like switching the stack.
global_asm!(include_str!("switch.S"));

extern "C" {
    /// Switches from this UEFI bootloader to the kernel init function (passes the sysinfo argument),
    /// kernel stack and kernel address space.
    fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: &SystemTable<Runtime>);
}


/// Make sure our UEFI version is not outdated.
fn check_revision(rev: uefi::table::Revision) {
    let (major, minor) = (rev.major(), rev.minor());
    assert!(major >= 2 && minor >= 30, "Require UEFI version >= 2.30");
}

/// Trying to get the file handle for the kernel binary.
fn locate_kernel_binary(st: &SystemTable<Boot>) -> RegularFile {
    let fhandle = st
        .boot_services()
        .locate_protocol::<SimpleFileSystem>()
        .expect_success("Don't have SimpleFileSystem support");
    let fhandle = unsafe { &mut *fhandle.get() };
    let mut root_file = fhandle.open_volume().expect_success("Can't open volume");

    // The kernel is supposed to be in the root folder of our EFI partition
    // in our case this is `target/x86_64-uefi/debug/esp/`
    // whereas the esp dir gets mounted with qemu using
    // `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
    let kernel_binary = "kernel";
    let kernel_file = root_file
        .open(
            format!("\\{}", kernel_binary).as_str(),
            FileMode::Read,
            FileAttribute::READ_ONLY,
        )
        .expect_success("Unable to locate `kernel` binary")
        .into_type()
        .expect_success("Can't cast it to a file common type??");

    let kernel_file: RegularFile = match kernel_file {
        FileType::Regular(t) => t,
        _ => panic!("kernel binary was found but is not a regular file type, check your build."),
    };

    debug!("Found the kernel binary");
    kernel_file
}

/// Determine the size of a regular file,
///
/// The only -- crappy -- way to do this with UEFI, seems to be
/// to seek to infinity and then call get_position on it?
fn determine_file_size(file: &mut RegularFile) -> usize {
    file.set_position(0xFFFFFFFFFFFFFFFF)
        .expect("Seek to the end of kernel");
    let file_size = file
        .get_position()
        .expect_success("Couldn't determine binary size") as usize;
    file.set_position(0)
        .expect("Reset file handle position failed");

    file_size
}

/// Allocates `pages` * `BASE_PAGE_SIZE` bytes of physical memory
/// and return the address.
fn allocate_pages(st: &SystemTable<Boot>, pages: usize, typ: MemoryType) -> PAddr {
    let num = st
        .boot_services()
        .allocate_pages(AllocateType::AnyPages, typ, pages)
        .expect_success(format!("Allocation of {} failed for type {:?}", pages, typ).as_str());

    // TODO: The UEFI Specification does not say if the pages we get are zeroed or not
    // (UEFI Specification 2.8, EFI_BOOT_SERVICES.AllocatePages())
    unsafe {
        st.boot_services()
            .memset(num as *mut u8, pages * BASE_PAGE_SIZE, 0u8)
    };

    PAddr::from(num)
}

/// Debug function to see what's currently in the UEFI address space.
#[allow(unused)]
fn dump_cr3() {
    unsafe {
        let cr_three: u64 = controlregs::cr3();
        debug!("current CR3: {:x}", cr_three);

        let pml4: PAddr = PAddr::from_u64(cr_three);
        let pml4_table = unsafe { transmute::<VAddr, &PML4>(paddr_to_kernel_vaddr(pml4)) };
        setup::dump_table(pml4_table);
    }
}

/// Start function of the bootloader.
/// The symbol name is defined through `/Entry:uefi_start` in `x86_64-uefi.json`.
#[no_mangle]
pub extern "C" fn uefi_start(handle: uefi::Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect("Can't initialize UEFI");
    debug!(
        "UEFI {}.{}",
        st.uefi_revision().major(),
        st.uefi_revision().minor()
    );
    info!("UEFI Bootloader starting...");
    check_revision(st.uefi_revision());

    // Get the kernel binary, this is just a plain old
    // ELF executable.
    let mut kernel_file = locate_kernel_binary(&st);
    let kernel_size = determine_file_size(&mut kernel_file);
    debug!("Found kernel binary with {} bytes", kernel_size);

    trace!("Load the kernel binary (in a vector)");
    let mut kernel_blob = alloc::vec::Vec::with_capacity(kernel_size);
    kernel_blob.resize(kernel_size, 0); // This is slow!
    kernel_file
        .read(kernel_blob.as_mut_slice())
        .expect("Can't read the kernel");

    // Next create an address space for our kernel
    trace!("Allocate a PML4 (page-table root)");
    let pml4: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
    let pml4_table = unsafe { transmute::<VAddr, &mut PML4>(paddr_to_kernel_vaddr(pml4)) };

    let mut kernel = Kernel {
        mapping: Vec::new(),
        vspace: VSpace { pml4: pml4_table },
    };

    // Parse the ELF file and load it into the new address space
    let binary = elfloader::ElfBinary::new("kernel", kernel_blob.as_slice()).unwrap();
    trace!("Load the ELF binary into the address space");
    binary.load(&mut kernel);

    // Make sure we still have access to the UEFI mappings:
    kernel.vspace.map_identity(
        VAddr::from(0x1000usize),
        VAddr::from(0x90000000usize + 65536 * 4096),
    );

    // Print the current memory map:
    let stack_pages = 128;
    let _map_key = boot::memory::memory_map(st.boot_services());
    let stack_base = allocate_pages(&st, stack_pages, MemoryType(KernelStack));
    let stack_top = stack_base.as_u64() + (stack_pages * BASE_PAGE_SIZE) as u64;
    assert_eq!(stack_top % 16, 0);
    debug!("Kernel stack starts at {:x}", stack_top);

    // Get an estimate of the memory map size:
    let mm_size_estimate = st.boot_services().memory_map_size();
    // Plan for some 32 more descriptors than original due to UEFI API crazyness,
    // round to page-size
    let mm_size = round_up!(
        mm_size_estimate + 32 * mem::size_of::<MemoryDescriptor>(),
        BASE_PAGE_SIZE
    );
    assert_eq!(mm_size % BASE_PAGE_SIZE, 0);
    let mm_paddr = allocate_pages(&st, mm_size / BASE_PAGE_SIZE, MemoryType(UefiMemoryMap));
    let mm_slice = unsafe {
        slice::from_raw_parts_mut(paddr_to_kernel_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size)
    };


    // Preparing to jump to the kernel
    // * Switch to new addres space
    // * Exit boot services
    // * Switch stack and do far jump (jump_to_kernel)
    unsafe {
        controlregs::cr3_write((kernel.vspace.pml4) as *const _ as u64);
        x86::tlb::flush_all();
        let cr_three: u64 = controlregs::cr3();
        debug!("Switched to kernel address space: {:x}", cr_three);
        // dump_cr3();

        info!("Jumping to kernel entry point {:#x}", binary.entry_point());

        // For debugging purposes, we can validate that the entry point
        // has the instruction that should be in the kernel binary at
        // the entry point address
        let slice = core::slice::from_raw_parts(binary.entry_point() as *const u8, 32);
        trace!("Kernel's first 32 bytes of instruction stream: {:?}", slice);

        // TODO: Firmware must ensure that timer event activity is stopped
        // before any of the EXIT_BOOT_SERVICES (watchdog?)

        // We exit the UEFI boot services
        let (st, mmiter) = st
            .exit_boot_services(handle, mm_slice)
            .expect_success("Can't exit the boot service");

        // It's unclear from the spec if `exit_boot_services` already disables interrupts
        // so we we make sure they are disabled:
        x86::irq::disable();

        // Finally switch to the kernel stack and entry function
        jump_to_kernel(stack_top, binary.entry_point(), &st);
    }

    unreachable!("UEFI Bootloader: We are not supposed to return here from the kernel?");
    uefi::Status(0xdead)
}

