//! A UEFI based bootloader for an x86-64 kernel.
//!
//! This code roughly does look for a kernel binary in the EFI partition,
//! loads it, then continues to construct an address space for it,
//! and finally it switches to the new address space and executes
//! the kernel entry function. In addition we gather a bit of information
//! about memory regions and pass this information on to the kernel.

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

use uefi::prelude::*;
use uefi::proto::media::file::*;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, BootServices, MemoryDescriptor, MemoryType};

use uefi_exts::BootServicesExt;

use crate::alloc::vec::Vec;

use x86::bits64::paging::*;
use x86::bits64::rflags;
use x86::controlregs;

mod boot;
mod proto;
mod setup;

use elfloader::elf;
use setup::*;

#[repr(C, packed)]
pub struct UEFIargs {
    pub minor: u64,
    pub major: u64,
    pub test: u64,
}

/// Include the `jump_to_kernel` assembly function. This does some things we can't express in
/// rust like switching the stack.
global_asm!(include_str!("switch.S"));
extern "C" {
    /// Switches from this UEFI bootloader to the kernel init function (passes the sysinfo argument),
    /// kernel stack and kernel address space.
    fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: &SystemTable<Boot>);
}


/// Make sure our UEFI version is not outdated.
fn check_revision(rev: uefi::table::Revision) {
    let (major, minor) = (rev.major(), rev.minor());
    assert!(major >= 2, "Running on an old, unsupported version of UEFI");
    assert!(
        minor >= 30,
        "Old version of UEFI 2, some features might not be available."
    );
}

/// Trying to get the file handle for the kernel binary.
fn locate_kernel_binary(st: &SystemTable<Boot>) -> RegularFile {
    let mut fhandle = st
        .boot_services()
        .locate_protocol::<SimpleFileSystem>()
        .expect_success("Don't have SimpleFileSystem support");
    let mut fhandle = unsafe { &mut *fhandle.get() };
    let mut root_file = fhandle.open_volume().expect_success("Can't open volume");

    // The kernel is supposed to be in the root folder of our EFI partition
    // in our case this is `target/x86_64-uefi/debug/esp/`
    // whereas the esp dir gets mounted with qemu using
    // `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
    let kernel_binary = "kernel";
    let mut kernel_file = root_file
        .open(
            format!("\\{}", kernel_binary).as_str(),
            FileMode::Read,
            FileAttribute::READ_ONLY,
        )
        .expect_success("Unable to locate `kernel` binary")
        .into_type()
        .expect_success("Can't cast it to a file common type??");

    let mut kernel_file: RegularFile = match kernel_file {
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


/// Start function of the bootloader.
/// The symbol name is defined through `/Entry:uefi_start` in `x86_64-uefi.json`.
#[no_mangle]
pub extern "C" fn uefi_start(_handle: uefi::Handle, st: SystemTable<Boot>) -> Status {
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
    let mut kernel_size = determine_file_size(&mut kernel_file);
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
    let map_key = boot::memory::memory_map(st.boot_services());

    unsafe {
        let cr_three: u64 = controlregs::cr3();
        let pml4: PAddr = PAddr::from_u64(cr_three);
        let pml4_table = unsafe { transmute::<VAddr, &PML4>(paddr_to_kernel_vaddr(pml4)) };
        //dump_table(pml4_table);

        info!("current CR3: {:x}", cr_three);
        info!("{:x}", x86::bits64::registers::rip());

        controlregs::cr3_write((kernel.vspace.pml4) as *const _ as u64);
        x86::tlb::flush_all();

        let cr_three: u64 = controlregs::cr3();
        info!("success with new CR3: {:x}", cr_three);
        let pml4: PAddr = PAddr::from_u64(cr_three);
        let pml4_table = unsafe { transmute::<VAddr, &PML4>(paddr_to_kernel_vaddr(pml4)) };

        let mut uefi_args = UEFIargs {
            minor: st.uefi_revision().minor() as u64,
            major: st.uefi_revision().major() as u64,
            test: 1,
        };
        info!("UEFI {}.{}", uefi_args.major, uefi_args.minor);

        //let arch_init_fn: extern "C" fn(uefi_arguments: &mut UEFIargs) -> ! = mem::transmute(binary.entry_point() as *const u64);
        let arch_init_fn: extern "sysv64" fn(st: SystemTable<Boot>) -> ! =
            mem::transmute(binary.entry_point() as *const u64);
        let static_ref: &'static UEFIargs = mem::transmute(&uefi_args);

        let num = st
            .boot_services()
            .allocate_pages(
                AllocateType::AnyPages,
                uefi::table::boot::MemoryType(KernelStack),
                64,
            )
            .expect_success("allocated things");
        st.boot_services()
            .memset(num as *mut u8, 64 * BASE_PAGE_SIZE, 0u8);
        setup::dump_table(pml4_table);
        info!("before flushing");

        info!("rsp is {:x}", x86::current::registers::rsp());
        info!(
            "Switch to kernel stack at {:x}",
            num as usize + 64 * BASE_PAGE_SIZE
        );

        info!(
            "about to jump {:p}",
            (binary.entry_point() as u64) as *const u64
        );
        x86::tlb::flush_all();

        let addr = (binary.entry_point() as u64);

        unsafe {
            let slice = core::slice::from_raw_parts(addr as *const u8, 32);
            info!("start fn of kernel is {:?}", slice);
        }
        x86::irq::disable();
        assert!((num as usize + 62 * BASE_PAGE_SIZE) % 16 == 0);
        jump_to_kernel((num as usize + 62 * BASE_PAGE_SIZE) as u64, addr, &st);
        info!("returned?");
    }

    uefi::Status(0)
}

