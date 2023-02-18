// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
//!    * PROTECTION_KEY
//!    * SMAP
//!    * SMEP
//!    * OS_XSAVE
//!    * FSGSBASE
//!    * UNMASKED_SSE
//!    * ENABLE_SSE
//!    * ENABLE_GLOBAL_PAGES
//!    * ENABLE_PAE
//!    * ENABLE_PSE
//!    * DEBUGGING_EXTENSIONS
//!    * ENABLE_MACHINE_CHECK
//!  * In IA32_EFER MSR, we enabled the following features
//!    * NSX (No execute bit): The constructed kernel page-tables already make use of the NSX bits
//!  * The kernel address space we switch to is set-up as follows:
//!    * All UEFI reported memory regions are 1:1 mapped phys <-> virt.
//!    * All UEFI reported memory regions are 1:1 mapped to the 'kernel physical space' (which is above KERNEL_BASE).
//!    * The kernel ELF binary is loaded somewhere in physical memory and relocated
//!      for running in the kernel-space above KERNEL_BASE.
//!  * A pointer to the KernelArgs struct is given as a first argument:
//!    * The memory allocated for it (and everything within) is pointing to kernel space
//!
//!  Not yet done:
//!    * the xAPIC region is remapped to XXX

#![no_std]
#![no_main]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

extern crate elfloader;
extern crate x86;

use core::arch::global_asm;
use core::mem::transmute;
use core::{mem, slice};

use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::table::boot::{AllocateType, MemoryDescriptor, MemoryType};
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};

use crate::alloc::vec::Vec;

use x86::bits64::paging::*;
use x86::controlregs;

mod kernel;
mod modules;
mod vspace;

use kernel::*;
use modules::*;
use vspace::*;

use bootloader_shared::*;

#[macro_export]
macro_rules! round_up {
    ($num:expr, $s:expr) => {
        (($num + $s - 1) / $s) * $s
    };
}

// Include the `jump_to_kernel` assembly function. This does some things we can't express in
// rust like switching the stack.
global_asm!(include_str!("switch.S"), options(att_syntax));

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

/// Allocates `pages` * `BASE_PAGE_SIZE` bytes of physical memory
/// and return the address.
pub fn allocate_pages(st: &SystemTable<Boot>, pages: usize, typ: MemoryType) -> PAddr {
    let num = st
        .boot_services()
        .allocate_pages(AllocateType::AnyPages, typ, pages)
        .expect(format!("Allocation of {} failed for type {:?}", pages, typ).as_str());

    // TODO: The UEFI Specification does not say if the pages we get are zeroed or not
    // (UEFI Specification 2.8, EFI_BOOT_SERVICES.AllocatePages())
    unsafe {
        st.boot_services()
            .set_mem(num as *mut u8, pages * BASE_PAGE_SIZE, 0u8)
    };

    PAddr::from(num)
}

/// Debug function to see what's currently in the UEFI address space.
#[allow(unused)]
fn dump_cr3() {
    unsafe {
        let cr_three: u64 = controlregs::cr3();
        debug!("current CR3: {:x}", cr_three);

        let pml4: PAddr = PAddr::from(cr_three);
        let pml4_table = unsafe { transmute::<VAddr, &PML4>(paddr_to_uefi_vaddr(pml4)) };
        vspace::dump_table(pml4_table);
    }
}

/// Find out how many pages we require to load the memory map
/// into it.
///
/// Plan for some 32 more descriptors than originally estimated,
/// due to UEFI API crazyness. Also round to page-size.
fn estimate_memory_map_size(st: &SystemTable<Boot>) -> (usize, usize) {
    let mm_size_estimate = st.boot_services().memory_map_size();
    // Plan for some 32 more descriptors than originally estimated,
    // due to UEFI API crazyness, round to page-size
    let sz = round_up!(
        mm_size_estimate.map_size + 32 * mm_size_estimate.entry_size,
        BASE_PAGE_SIZE
    );
    assert_eq!(sz % BASE_PAGE_SIZE, 0, "Not multiple of page-size.");

    (sz, sz / mem::size_of::<MemoryDescriptor>())
}

/// Load the memory map into buffer (which is hopefully big enough).
fn map_physical_memory(st: &SystemTable<Boot>, kernel: &mut Kernel) {
    let (mm_size, _no_descs) = estimate_memory_map_size(st);
    let mm_paddr = allocate_pages(&st, mm_size / BASE_PAGE_SIZE, MemoryType(UEFI_MEMORY_MAP));
    let mm_slice: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(paddr_to_uefi_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size)
    };

    let (_key, desc_iter) = st
        .boot_services()
        .memory_map(mm_slice)
        .expect("Failed to retrieve UEFI memory map");

    for entry in desc_iter {
        if entry.phys_start == 0x0 {
            debug!("Don't map memory entry at physical zero? {:#?}", entry);
            continue;
        }

        // Compute physical base and bound for the region we're about to map
        let phys_range_start = PAddr::from(entry.phys_start);
        let phys_range_end =
            PAddr::from(entry.phys_start + entry.page_count * BASE_PAGE_SIZE as u64);

        if phys_range_start.as_u64() <= 0xfee00000u64 && phys_range_end.as_u64() >= 0xfee00000u64 {
            debug!("{:?} covers APIC range, ignore for now.", entry);
            continue;
        }

        let rights: MapAction = match entry.ty {
            MemoryType::RESERVED => MapAction::None,
            MemoryType::LOADER_CODE => MapAction::ReadExecuteKernel,
            MemoryType::LOADER_DATA => MapAction::ReadWriteKernel,
            MemoryType::BOOT_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::BOOT_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::RUNTIME_SERVICES_CODE => MapAction::ReadExecuteKernel,
            MemoryType::RUNTIME_SERVICES_DATA => MapAction::ReadWriteKernel,
            MemoryType::CONVENTIONAL => MapAction::ReadWriteExecuteKernel,
            MemoryType::UNUSABLE => MapAction::None,
            MemoryType::ACPI_RECLAIM => MapAction::ReadWriteKernel,
            MemoryType::ACPI_NON_VOLATILE => MapAction::ReadWriteKernel,
            MemoryType::MMIO => MapAction::ReadWriteKernel,
            MemoryType::MMIO_PORT_SPACE => MapAction::ReadWriteKernel,
            MemoryType::PAL_CODE => MapAction::ReadExecuteKernel,
            MemoryType::PERSISTENT_MEMORY => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_ELF) => MapAction::ReadKernel,
            MemoryType(KERNEL_PT) => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_STACK) => MapAction::ReadWriteKernel,
            MemoryType(UEFI_MEMORY_MAP) => MapAction::ReadWriteKernel,
            MemoryType(KERNEL_ARGS) => MapAction::ReadKernel,
            MemoryType(MODULE) => MapAction::ReadKernel,
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

            if entry.ty == MemoryType::CONVENTIONAL
                // We're allowed to use these regions according to the spec  after we call ExitBootServices.
                // Also it can sometimes happens that the regions here switch from this type back
                // to conventional if we're not careful with memory allocations between the call
                // to `map_physical_memory` until getting the final memory mapped before booting..
                || entry.ty == MemoryType::BOOT_SERVICES_DATA
                || entry.ty == MemoryType::LOADER_DATA
                // These are regions we need to access in kernel space:
                || entry.ty == MemoryType(KERNEL_PT)
                || entry.ty == MemoryType(MODULE)
                || entry.ty == MemoryType(KERNEL_ARGS)
            {
                kernel.vspace.map_identity_with_offset(
                    PAddr::from(KERNEL_OFFSET as u64),
                    phys_range_start,
                    phys_range_end,
                    rights,
                );
            }
        }
    }
}

/// Initialize the screen to the highest possible resolution.
fn _setup_screen(st: &SystemTable<Boot>) {
    if let Ok(gop) = st.boot_services().locate_protocol::<GraphicsOutput>() {
        let gop = unsafe { &mut *gop.get() };
        let _mode = gop
            .modes()
            .max_by(|ref x, ref y| x.info().resolution().cmp(&y.info().resolution()))
            .unwrap();
    } else {
        warn!("UEFI Graphics Output Protocol is not supported.");
    }
}

/// Intialize the serial console.
fn _serial_init(st: &SystemTable<Boot>) {
    use uefi::proto::console::serial::{ControlBits, Serial};
    if let Ok(serial) = st.boot_services().locate_protocol::<Serial>() {
        let serial = unsafe { &mut *serial.get() };

        let _old_ctrl_bits = serial
            .get_control_bits()
            .expect("Failed to get device control bits");

        let mut ctrl_bits = ControlBits::empty();
        ctrl_bits |= ControlBits::HARDWARE_FLOW_CONTROL_ENABLE;
        ctrl_bits |= ControlBits::SOFTWARE_LOOPBACK_ENABLE;

        serial
            .set_control_bits(ctrl_bits)
            .expect("Failed to set device control bits");

        const OUTPUT: &[u8] = b"Serial output check";
        const MSG_LEN: usize = OUTPUT.len();
        serial
            .write(OUTPUT)
            .expect("Failed to write to serial port");
    } else {
        warn!("No serial device found.");
    }
}

/// Make sure the machine supports what we require.
fn assert_required_cpu_features() {
    let cpuid = x86::cpuid::CpuId::new();

    let fi = cpuid.get_feature_info();
    let has_xsave = fi.as_ref().map_or(false, |f| f.has_xsave());
    let has_sse = fi.as_ref().map_or(false, |f| f.has_sse());
    let has_apic = fi.as_ref().map_or(false, |f| f.has_apic());
    let has_x2apic = fi.as_ref().map_or(false, |f| f.has_x2apic());
    let has_tsc = fi.as_ref().map_or(false, |f| f.has_tsc());
    let has_pae = fi.as_ref().map_or(false, |f| f.has_pae());
    let has_pse = fi.as_ref().map_or(false, |f| f.has_pse());
    let has_msr = fi.as_ref().map_or(false, |f| f.has_msr());
    let has_sse3 = fi.as_ref().map_or(false, |f| f.has_sse3());
    let has_osfxsr = fi.as_ref().map_or(false, |f| f.has_fxsave_fxstor());

    let efi = cpuid.get_extended_feature_info();
    let has_smap = efi.as_ref().map_or(false, |f| f.has_smap());
    let has_smep = efi.as_ref().map_or(false, |f| f.has_smep());
    let has_fsgsbase = efi.as_ref().map_or(false, |f| f.has_fsgsbase());

    let efni = cpuid.get_extended_processor_and_feature_identifiers();
    let has_1gib_pages = efni.as_ref().map_or(false, |f| f.has_1gib_pages());
    let has_rdtscp = efni.as_ref().map_or(false, |f| f.has_rdtscp());
    let has_syscall_sysret = efni.as_ref().map_or(false, |f| f.has_syscall_sysret());
    let has_execute_disable = efni.as_ref().map_or(false, |f| f.has_execute_disable());

    let apmi = cpuid.get_advanced_power_mgmt_info();
    let has_invariant_tsc = apmi.as_ref().map_or(false, |f| f.has_invariant_tsc());

    assert!(has_sse3);
    assert!(has_osfxsr);
    assert!(has_smap);
    assert!(has_smep);
    assert!(has_xsave);
    assert!(has_fsgsbase);
    assert!(has_sse);
    assert!(has_apic);
    assert!(has_x2apic); // If you fail here it probably means qemu wasn't running with KVM enabled...
    assert!(has_tsc);
    assert!(has_pae);
    assert!(has_pse);
    assert!(has_msr);
    assert!(has_1gib_pages);
    assert!(has_rdtscp);
    assert!(has_syscall_sysret);
    assert!(has_execute_disable);
    assert!(has_invariant_tsc);

    debug!("CPU has all required features, continue");
}

/// Start function of the bootloader.
/// The symbol name is defined through `/Entry:uefi_start` in `x86_64-uefi.json`.
#[no_mangle]
pub extern "C" fn uefi_start(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("Can't initialize UEFI");
    log::set_max_level(log::LevelFilter::Info);
    //setup_screen(&st);
    //serial_init(&st);

    debug!(
        "UEFI {}.{}",
        st.uefi_revision().major(),
        st.uefi_revision().minor()
    );
    info!("UEFI Bootloader starting...");
    check_revision(st.uefi_revision());

    let modules = load_modules_on_all_sfs(&st, "\\");

    let (kernel_blob, cmdline_blob) = {
        let mut kernel_blob = None;
        let mut cmdline_blob = None;
        for (name, m) in modules.iter() {
            if name == "kernel" {
                // This needs to be in physical space, because we relocate it in the bootloader
                kernel_blob = unsafe { Some(m.as_pslice()) };
            }
            if name == "cmdline.in" {
                // This needs to be in kernel-space because we ultimately access it in the kernel
                cmdline_blob = unsafe { Some(m.as_pslice()) };
                trace!("cmdline.in blob is at {:#x}", m.binary_paddr);
            }
        }

        (
            kernel_blob.expect("Didn't find kernel binary."),
            cmdline_blob.expect("Didn't find cmdline.in"),
        )
    };

    // Next create an address space for our kernel
    trace!("Allocate a PML4 (page-table root)");
    let pml4: PAddr = VSpace::allocate_one_page();
    let pml4_table = unsafe { &mut *paddr_to_uefi_vaddr(pml4).as_mut_ptr::<PML4>() };

    let mut kernel = Kernel {
        offset: VAddr::from(0usize),
        mapping: Vec::new(),
        vspace: VSpace { pml4: pml4_table },
        tls: None,
    };

    // Parse the ELF file and load it into the new address space
    let binary = elfloader::ElfBinary::new(kernel_blob).unwrap();
    trace!("Load the ELF binary into the address space");
    binary.load(&mut kernel).expect("Can't load the kernel");

    // On big machines with the init stack tends to put big structures
    // on the stack so we reserve a fair amount of space:
    let stack_pages: usize = 1024;
    let stack_region: PAddr = allocate_pages(&st, stack_pages, MemoryType(KERNEL_STACK));
    let stack_protector: PAddr = stack_region;
    let stack_base: PAddr = stack_region + BASE_PAGE_SIZE;

    let stack_size: usize = (stack_pages - 1) * BASE_PAGE_SIZE;
    let stack_top: PAddr = stack_base + stack_size as u64;
    assert_eq!(stack_protector + BASE_PAGE_SIZE, stack_base);

    kernel.vspace.map_identity_with_offset(
        PAddr::from(KERNEL_OFFSET as u64),
        stack_protector,
        stack_protector + BASE_PAGE_SIZE,
        MapAction::ReadUser, // TODO: should be MapAction::None
    );
    kernel.vspace.map_identity_with_offset(
        PAddr::from(KERNEL_OFFSET as u64),
        stack_base,
        stack_top,
        MapAction::ReadWriteKernel,
    );
    debug!(
        "Init stack memory: {:#x} -- {:#x} (protector at {:#x} -- {:#x})",
        stack_base.as_u64(),
        stack_top.as_u64(),
        stack_protector,
        stack_protector + BASE_PAGE_SIZE,
    );
    assert!(mem::size_of::<KernelArgs>() < BASE_PAGE_SIZE);
    let kernel_args_paddr = allocate_pages(&st, 1, MemoryType(KERNEL_ARGS));

    // Make sure we still have access to the UEFI mappings:
    // Get the current memory map and 1:1 map all physical memory
    // dump_cr3();
    map_physical_memory(&st, &mut kernel);
    trace!("Replicated UEFI memory map");
    assert_required_cpu_features();

    unsafe {
        // Enable cr4 features
        use x86::controlregs::{cr4, cr4_write, Cr4};
        let old_cr4 = cr4();
        let new_cr4 = Cr4::CR4_ENABLE_SMAP
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
        debug!("Switched to new page-table.");

        // Enable NXE bit (11)
        use x86::msr::{rdmsr, wrmsr, IA32_EFER};
        let efer = rdmsr(IA32_EFER) | 1 << 11;
        wrmsr(IA32_EFER, efer);
    }

    unsafe {
        // Preparing to jump to the kernel
        // * Switch to the kernel address space
        // * Exit boot services
        // * Switch stack and do a jump to kernel ELF entry point
        // Get an estimate of the memory map size:
        let (mm_size, no_descs) = estimate_memory_map_size(&st);
        assert_eq!(mm_size % BASE_PAGE_SIZE, 0);
        let mm_paddr = allocate_pages(&st, mm_size / BASE_PAGE_SIZE, MemoryType(UEFI_MEMORY_MAP));
        let mm_slice =
            slice::from_raw_parts_mut(paddr_to_uefi_vaddr(mm_paddr).as_mut_ptr::<u8>(), mm_size);
        trace!("Memory map allocated.");

        // Construct a KernelArgs struct that gets passed to the kernel
        // This could theoretically be pushed on the stack too
        // but for now we just allocate a separate page (and don't care about
        // wasted memory)
        let mut kernel_args =
            transmute::<VAddr, &mut KernelArgs>(paddr_to_uefi_vaddr(kernel_args_paddr));
        trace!("Kernel args allocated at {:#x}.", kernel_args_paddr);
        kernel_args.mm_iter = Vec::with_capacity(no_descs);

        // Initialize the KernelArgs
        kernel_args.command_line = core::str::from_utf8_unchecked(cmdline_blob);
        kernel_args.mm = (mm_paddr + KERNEL_OFFSET, mm_size);
        kernel_args.pml4 = PAddr::from(kernel.vspace.pml4 as *const _ as u64);
        kernel_args.stack = (stack_base + KERNEL_OFFSET, stack_size);
        kernel_args.kernel_elf_offset = kernel.offset;
        kernel_args.tls_info = kernel.tls;
        kernel_args.modules = arrayvec::ArrayVec::new();
        // Add modules to kernel args, ensure 'kernel' is first:
        for (name, module) in modules.iter() {
            if name == "kernel" {
                kernel_args.modules.push(module.clone());
            }
        }
        for (name, module) in modules {
            if name != "kernel" {
                kernel_args.modules.push(module);
            }
        }
        for entry in st.config_table() {
            if entry.guid == ACPI2_GUID {
                kernel_args.acpi2_rsdp = PAddr::from(entry.address as u64);
            } else if entry.guid == ACPI_GUID {
                kernel_args.acpi1_rsdp = PAddr::from(entry.address as u64);
            }
        }

        if let Ok(gop) = st.boot_services().locate_protocol::<GraphicsOutput>() {
            let gop = &mut *gop.get();

            let mut frame_buffer = gop.frame_buffer();
            let frame_buf_ptr = frame_buffer.as_mut_ptr();
            let size = frame_buffer.size();
            let _frame_buf_paddr = PAddr::from(frame_buf_ptr as u64);

            kernel_args.frame_buffer = Some(core::slice::from_raw_parts_mut(
                frame_buf_ptr.add(KERNEL_OFFSET),
                size,
            ));
            kernel_args.mode_info = Some(gop.current_mode_info());
        } else {
            kernel_args.frame_buffer = None;
            kernel_args.mode_info = None;
        }

        info!(
            "Kernel will start to execute from: {:p}",
            kernel.offset + binary.entry_point()
        );

        info!("Exiting boot services. About to jump...");
        let (_st, mmiter) = st
            .exit_boot_services(handle, mm_slice)
            .expect("Can't exit the boot service");
        // FYI: Print no longer works here... so let's hope we make
        // it to the kernel serial init

        kernel_args.mm_iter.extend(mmiter);

        // It's unclear from the spec if `exit_boot_services` already disables interrupts
        // so we we make sure they are disabled (otherwise we triple fault since
        // we don't have an IDT setup in the beginning)
        x86::irq::disable();

        // Switch to the kernel address space
        controlregs::cr3_write((kernel.vspace.pml4) as *const _ as u64);

        // Finally switch to the kernel stack and entry function
        jump_to_kernel(
            KERNEL_OFFSET as u64 + stack_top.as_u64() - (BASE_PAGE_SIZE as u64),
            kernel.offset.as_u64() + binary.entry_point(),
            paddr_to_kernel_vaddr(kernel_args_paddr).as_u64(),
        );

        unreachable!("UEFI Bootloader: We are not supposed to return here from the kernel?");
    }
}
