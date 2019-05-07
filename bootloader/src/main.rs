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
//!  * In CR4, we enabled the following features
//!    PROTECTION_KEY, SMAP, SMEP, OS_XSAVE, FSGSBASE, UNMASKED_SSE, ENABLE_SSE,
//!    ENABLE_GLOBAL_PAGES, ENABLE_PAE, ENABLE_PSE, DEBUGGING_EXTENSIONS,
//!    ENABLE_MACHINE_CHECK
//!  * In IA32_EFER MSR, we enabled the following features
//!    NSX (No execute bit)
//!  * The address space that we switch to is as follows:
//!    * All UEFI reported memory regions are 1:1 mapped phys <-> virt as kernel readable-writeable.
//!    * XXX: All UEFI reported memory regions are 1:1 mirrored in the kernel address region (above KERNEL_BASE)
//!    * XXX: The kernel ELF binary loaded in physical memory and relocated for running in the space above KERNEL_BASE.
//!  * A pointer to the KernelArgs struct is given as a first argument:
//!    * The memory allocated for it (and everything within) points to the kernel address region (XXX)
//!
//!  Not yet done:
//!    * the xAPIC region is remapped to XXX

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
use uefi::table::boot::{
    AllocateType, BootServices, MemoryDescriptor, MemoryMapIter, MemoryMapKey, MemoryType,
};
use uefi::table::Runtime;

use crate::alloc::vec::Vec;

use x86::bits64::paging::*;

use x86::controlregs;

mod boot;
mod setup;
mod shared;

use setup::*;
use shared::*;

macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

// Include the `jump_to_kernel` assembly function. This does some things we can't express in
// rust like switching the stack.
global_asm!(include_str!("switch.S"));

extern "C" {
    /// Switches from this UEFI bootloader to the kernel init function (passes the sysinfo argument),
    /// kernel stack and kernel address space.
    fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64);
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

/// Find out how many pages we require to load the memory map
/// into it.
///
/// Plan for some 32 more descriptors than originally estimated,
/// due to UEFI API crazyness. Also round to page-size.
fn estimate_memory_map_size(st: &SystemTable<Boot>) -> usize {
    let mm_size_estimate = st.boot_services().memory_map_size();
    // Plan for some 32 more descriptors than originally estimated,
    // due to UEFI API crazyness, round to page-size
    let sz = round_up!(
        mm_size_estimate + 32 * mem::size_of::<MemoryDescriptor>(),
        BASE_PAGE_SIZE
    );
    assert_eq!(sz % BASE_PAGE_SIZE, 0, "Not multiple of page-size.");

    sz
}

/// Load the memory map into buffer (which is hopefully big enough).
fn map_physical_memory(st: &SystemTable<Boot>, kernel: &mut Kernel) {
    let mm_size = estimate_memory_map_size(st);
    let mm_paddr = allocate_pages(&st, mm_size / BASE_PAGE_SIZE, MemoryType(UefiMemoryMap));
    let mut mm_slice: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(paddr_to_kernel_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size)
    };

    let (key, mut desc_iter) = st
        .boot_services()
        .memory_map(mm_slice)
        .expect_success("Failed to retrieve UEFI memory map");
    assert!(desc_iter.len() > 0, "Memory map is empty");

    for entry in desc_iter {
        if 0x0 != entry.virt_start {
            info!(
                "xxxxx {:#x} -- {:#x} {:?} {:?}",
                entry.phys_start,
                entry.phys_start + entry.page_count * BASE_PAGE_SIZE as u64,
                entry.ty,
                entry.att
            );
        }

        if entry.phys_start == 0x0 {
            debug!("Don't map memory entry at physical zero? {:#?}", entry);
            continue;
        }

        // Compute physical base and bound for the region we're about to map
        let phys_range_start = PAddr::from(entry.phys_start);
        let phys_range_end =
            PAddr::from(entry.phys_start + entry.page_count * BASE_PAGE_SIZE as u64);

        let rights: MapAction = match entry.ty {
            MemoryType::RESERVED => MapAction::None,
            MemoryType::LOADER_CODE => MapAction::ReadExecuteKernel,
            MemoryType::LOADER_DATA => MapAction::ReadWriteKernel,
            MemoryType::BOOT_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::BOOT_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::RUNTIME_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::RUNTIME_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::CONVENTIONAL => MapAction::ReadWriteKernel,
            MemoryType::UNUSABLE => MapAction::None,
            MemoryType::ACPI_RECLAIM => MapAction::ReadWriteKernel,
            MemoryType::ACPI_NON_VOLATILE => MapAction::ReadWriteKernel,
            MemoryType::MMIO => MapAction::ReadWriteKernel,
            MemoryType::MMIO_PORT_SPACE => MapAction::ReadWriteKernel,
            MemoryType::PAL_CODE => MapAction::ReadExecuteKernel,
            MemoryType::PERSISTENT_MEMORY => MapAction::ReadWriteKernel,
            MemoryType(KernelElf) => MapAction::ReadKernel,
            MemoryType(KernelPT) => MapAction::ReadWriteKernel,
            MemoryType(KernelStack) => MapAction::ReadWriteKernel,
            MemoryType(UefiMemoryMap) => MapAction::ReadWriteKernel,
            _ => {
                error!("Unknown memory type, what should we do? {:#?}", entry);
                MapAction::None
            }
        };

        debug!(
            "Doing {:?} on {:#x} -- {:#x}",
            rights, phys_range_start, phys_range_end
        );
        if rights != MapAction::None {
            kernel
                .vspace
                .map_identity(phys_range_start, phys_range_end, rights);

            if entry.ty == MemoryType::CONVENTIONAL {
                /*kernel.vspace.map_identity_with_offset(
                    PAddr::from(2 * KERNEL_OFFSET as u64),
                    phys_range_start,
                    phys_range_end,
                    rights,
                );*/
            }
        }
    }

    /// TODO: ReMap the APIC at a different address...
    kernel.vspace.map_identity(
        PAddr(0xfee00000u64),
        PAddr(0xfee00000u64 + BASE_PAGE_SIZE as u64),
        MapAction::ReadWriteExecuteKernel,
    );
}

/// Start function of the bootloader.
/// The symbol name is defined through `/Entry:uefi_start` in `x86_64-uefi.json`.
#[no_mangle]
pub extern "C" fn uefi_start(handle: uefi::Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st).expect("Can't initialize UEFI");
    log::set_max_level(log::LevelFilter::Info);

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
    let kernel_base_paddr = allocate_pages(
        &st,
        round_up!(kernel_size, BASE_PAGE_SIZE) / BASE_PAGE_SIZE,
        MemoryType(UefiMemoryMap),
    );
    trace!("Load the kernel binary (in a vector)");
    let mut kernel_blob: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(
            paddr_to_kernel_vaddr(kernel_base_paddr).as_mut_ptr::<u8>(),
            kernel_size,
        )
    };
    kernel_file
        .read(kernel_blob)
        .expect("Can't read the kernel");

    // Next create an address space for our kernel
    trace!("Allocate a PML4 (page-table root)");
    let pml4: PAddr = VSpace::allocate_one_page();
    let pml4_table = unsafe { &mut *paddr_to_kernel_vaddr(pml4).as_mut_ptr::<PML4>() };

    let mut kernel = Kernel {
        allocated: false,
        offset: VAddr::from(KERNEL_OFFSET),
        mapping: Vec::new(),
        vspace: VSpace { pml4: pml4_table },
    };

    // Parse the ELF file and load it into the new address space
    let binary = elfloader::ElfBinary::new("kernel", kernel_blob).unwrap();
    trace!("Load the ELF binary into the address space");
    binary.load(&mut kernel).expect("Can't load the kernel");

    trace!("Kernel stack allocation");
    let stack_pages = 128;
    let stack_base = allocate_pages(&st, stack_pages, MemoryType(KernelStack));
    let stack_top = stack_base.as_u64() + (stack_pages * BASE_PAGE_SIZE) as u64;
    assert_eq!(stack_top % 16, 0);
    debug!("Kernel stack starts at {:x}", stack_top);

    // Make sure we still have access to the UEFI mappings:
    // Get the current memory map and 1:1 map all physical memory
    // dump_cr3();
    map_physical_memory(&st, &mut kernel);
    trace!("Replicated UEFI memory map");

    unsafe {
        // Enable cr4 features
        use x86::controlregs::{cr4, cr4_write, Cr4};
        let old_cr4 = x86::controlregs::cr4();
        let new_cr4 = Cr4::CR4_ENABLE_PROTECTION_KEY
            | Cr4::CR4_ENABLE_SMAP
            | Cr4::CR4_ENABLE_SMEP
            | Cr4::CR4_ENABLE_OS_XSAVE
            | Cr4::CR4_ENABLE_FSGSBASE
            | Cr4::CR4_UNMASKED_SSE
            | Cr4::CR4_ENABLE_SSE
            | Cr4::CR4_ENABLE_GLOBAL_PAGES
            | Cr4::CR4_ENABLE_PAE
            | Cr4::CR4_ENABLE_PSE
            | Cr4::CR4_DEBUGGING_EXTENSIONS
            | Cr4::CR4_ENABLE_MACHINE_CHECK;

        cr4_write(new_cr4);
        if !new_cr4.contains(old_cr4) {
            warn!("UEFI has too many CR4 features enabled, so we disabled some: new cr4 {:?}, uefi cr4 was = {:?}", new_cr4, old_cr4);
        }

        // Enable NXE bit (11)
        use x86::msr::{rdmsr, wrmsr, IA32_EFER};
        let efer = rdmsr(IA32_EFER) | 1 << 11;
        wrmsr(IA32_EFER, efer);
    }

    // Preparing to jump to the kernel
    // * Switch to the kernel address space
    // * Exit boot services
    // * Switch stack and do a jump to kernel ELF entry point
    unsafe {
        // Get an estimate of the memory map size:
        let mm_size = estimate_memory_map_size(&st);
        assert_eq!(mm_size % BASE_PAGE_SIZE, 0);
        let mm_paddr = allocate_pages(&st, mm_size / BASE_PAGE_SIZE, MemoryType(UefiMemoryMap));
        let mm_slice = unsafe {
            slice::from_raw_parts_mut(paddr_to_kernel_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size)
        };
        trace!("Memory map allocated.");

        // Construct a KernelArgs struct that gets passed to the kernel
        // This could theoretically be pushed on the stack too
        // but for now we just allocate a separate page (and don't care about
        // wasted memory)
        assert!(mem::size_of::<KernelArgs>() < BASE_PAGE_SIZE);
        let kernel_args_paddr = allocate_pages(&st, 1, MemoryType(KernelArgs));
        let mut kernel_args = unsafe {
            transmute::<VAddr, &mut KernelArgs>(paddr_to_kernel_vaddr(kernel_args_paddr))
        };
        trace!("Kernel args allocated.");

        // Initialize the KernelArgs
        kernel_args.mm = (mm_paddr, mm_size);
        kernel_args.pml4 = PAddr::from(kernel.vspace.pml4 as *const _ as u64);
        kernel_args.stack = (stack_base, stack_pages * BASE_PAGE_SIZE);
        kernel_args.kernel_binary = (kernel_base_paddr, kernel_size);

        info!(
            "Kernel will execute at: {:p}",
            kernel.offset + binary.entry_point()
        );

        // TODO: Firmware must ensure that timer event activity is stopped
        // before any of the EXIT_BOOT_SERVICES (watchdog?)

        // We exit the UEFI boot services (and record the memory map)
        info!("Exiting boot services.");
        let (st, mmiter) = st
            .exit_boot_services(handle, mm_slice)
            .expect_success("Can't exit the boot service");
        // Print no longer works here... so let's hope we make it to the kernel
        kernel_args.mm_iter = mmiter;

        // It's unclear from the spec if `exit_boot_services` already disables interrupts
        // so we we make sure they are disabled (otherwise we triple fault since
        // we don't have an IDT setup in the beginning)
        x86::irq::disable();

        // Switch to the kernel address space
        controlregs::cr3_write((kernel.vspace.pml4) as *const _ as u64);
        x86::tlb::flush_all();

        // Finally switch to the kernel stack and entry function
        jump_to_kernel(
            stack_top,
            kernel.offset.as_u64() + binary.entry_point(),
            kernel_args_paddr.0,
        );
    }

    unreachable!("UEFI Bootloader: We are not supposed to return here from the kernel?");
    uefi::Status(0xdead)
}
