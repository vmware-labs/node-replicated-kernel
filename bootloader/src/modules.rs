// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Code to handle the loading of OS ELF modules from the UEFI file system.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::{fmt, slice};

use uefi::prelude::*;
use uefi::proto::media::file::*;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::MemoryType;
use uefi::{CStr16, Char16};
use x86::bits64::paging::BASE_PAGE_SIZE;

use crate::kernel::{paddr_to_kernel_vaddr, paddr_to_uefi_vaddr, MODULE};
use crate::{allocate_pages, round_up, KernelArgs, Module};

const MAX_FILE_NAME_LEN: usize = 255;

/// Trying to get the file handle for the kernel binary.
fn locate_binary(_st: &SystemTable<Boot>, directory: &mut Directory, name: &str) -> RegularFile {
    // Look for the given binary name in the root folder of our EFI partition
    // in our case this is `target/x86_64-uefi/debug/esp/`
    // whereas the esp dir gets mounted with qemu using
    // `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
    let mut c16_buf = [0; MAX_FILE_NAME_LEN];
    let c16_name = CStr16::from_str_with_buf(format!("{}", name).as_str(), &mut c16_buf).unwrap();

    let binary_file = directory
        .open(c16_name, FileMode::Read, FileAttribute::READ_ONLY)
        .expect(format!("Unable to locate binary '{}'", name).as_str())
        .into_type()
        .expect("Can't cast it to a file common type??");

    let binary_file: RegularFile = match binary_file {
        FileType::Regular(t) => t,
        _ => panic!("Binary was found but is not a regular file type, check your build."),
    };

    debug!("Found the binary {}", name);
    binary_file
}

/// Determine the size of a regular file,
///
/// The only -- crappy -- way to do this with UEFI, seems to be
/// to seek to infinity and then call get_position on it?
fn determine_file_size(file: &mut RegularFile) -> usize {
    file.set_position(0xFFFFFFFFFFFFFFFF)
        .expect("Seek to the end of kernel");
    let file_size = file.get_position().expect("Couldn't determine binary size") as usize;
    file.set_position(0)
        .expect("Reset file handle position failed");

    file_size
}

/// Load a binary from the UEFI FAT partition, and return
/// a slice to the data in memory along with a Module struct
/// that can be passed to the kernel.
pub fn load_binary_into_memory(
    st: &SystemTable<Boot>,
    dir: &mut Directory,
    _file: &mut uefi::proto::media::file::FileInfo,
    name: &str,
) -> Module {
    // Get the binary, this should be a plain old
    // ELF executable.
    let mut module_file = locate_binary(&st, dir, name);
    let module_size = determine_file_size(&mut module_file);
    debug!("Found {} binary with {} bytes", name, module_size);
    let module_base_paddr = allocate_pages(
        &st,
        round_up!(module_size, BASE_PAGE_SIZE) / BASE_PAGE_SIZE,
        MemoryType(MODULE),
    );
    trace!("Load the {} binary (in a vector)", name);
    let module_blob: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(
            paddr_to_uefi_vaddr(module_base_paddr).as_mut_ptr::<u8>(),
            module_size,
        )
    };
    module_file
        .read(module_blob)
        .expect("Can't read the module file");

    Module::new(
        name,
        paddr_to_kernel_vaddr(module_base_paddr),
        module_base_paddr,
        module_size,
    )
}

/// Look for all files in the root folder all SimpleFileSystems that are registered.
///
/// When running on qemu this is likely the esp partition in `target/x86_64-uefi/debug/esp/`
/// the esp dir gets mounted with qemu using `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
///
/// When running on bare-metal, ipxe registers its own virtual file system where modules are stored.
pub fn load_modules_on_all_sfs(st: &SystemTable<Boot>, _dir_name: &str) -> Vec<(String, Module)> {
    let all_handles = st
        .boot_services()
        .find_handles::<SimpleFileSystem>()
        .expect("Can't find any SimpleFileSystems?");
    let mut modules: Vec<(String, Module)> = Vec::with_capacity(KernelArgs::MAX_MODULES);
    for handle in all_handles {
        let fhandle = st
            .boot_services()
            .handle_protocol::<SimpleFileSystem>(handle)
            .expect("Don't have SimpleFileSystem support");
        let fhandle = unsafe { &mut *fhandle.get() };
        modules.extend(load_modules(st, fhandle));
    }

    modules
}

/// Walk through the root directory of the UEFI SimpleFileSystem
/// and return all files we find in that directory as
/// a list tuples (filename, module).
///
/// Does not recurse into subdirectories.
pub fn load_modules(
    st: &SystemTable<Boot>,
    fhandle: &mut SimpleFileSystem,
) -> Vec<(String, Module)> {
    let mut dir_handle = fhandle.open_volume().expect("Can't open volume");

    // We have capacity for 32 modules if you want to increase this
    // also change `modules` in KernelArgs.
    let mut modules = Vec::with_capacity(KernelArgs::MAX_MODULES);

    for _m in 0..KernelArgs::MAX_MODULES {
        const MAX_FILE_INFO_SIZE: usize = 256;
        let mut buffer: &mut [u8] = &mut [0u8; MAX_FILE_INFO_SIZE];

        match dir_handle.read_entry(&mut buffer) {
            Ok(completion) => {
                if let Some(file_info) = completion {
                    let file_name_16 = DCStr16(file_info.file_name().as_ptr());
                    if !file_info.attribute().contains(FileAttribute::DIRECTORY) {
                        let name_string: String = file_name_16.into();
                        debug!("about to load {}", name_string);
                        if name_string != "BootX64.efi" && name_string.len() < Module::MAX_NAME_LEN
                        {
                            let module = load_binary_into_memory(
                                st,
                                &mut dir_handle,
                                file_info,
                                name_string.as_str(),
                            );
                            modules.push((name_string, module));
                        } else if name_string.len() >= Module::MAX_NAME_LEN {
                            // Ignore modules with long name (since they would be truncated in Module)
                            // if you want to change this increase `Module::MAX_NAME_LEN`
                            error!("File {} exceeds Module::MAX_NAME_LEN", name_string);
                        }
                    } else {
                        // Ignore directory entries
                        let name_string: String = file_name_16.into();
                        trace!("Found directory {}", name_string);
                    }
                }
            }
            Err(e) => {
                error!("Can't read directory entry while loading module: {:?}", e);
            }
        }
    }

    if modules.len() == KernelArgs::MAX_MODULES {
        error!("We loaded KernelArgs::MAX_MODULES modules and stopped loading after that, maybe increase bootloader parameters?")
    }

    modules
}

/// Silly wrapper around CStr16.
///
/// Because `Display` is not defined for `CStr16`
/// (remove this when https://github.com/rust-osdev/uefi-rs/issues/98 is implemented)
struct DCStr16(*const Char16);

impl Into<String> for DCStr16 {
    fn into(self) -> String {
        let s = unsafe { CStr16::from_ptr(self.0) };

        let mut rust_string = String::with_capacity(s.to_u16_slice().len());
        for x in s.to_u16_slice() {
            if let Ok(u16c) = Char16::try_from(*x) {
                if let Ok(rch) = char::try_from(u16c) {
                    rust_string.push(rch);
                }
            }
        }

        rust_string
    }
}

impl fmt::Display for DCStr16 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = unsafe { CStr16::from_ptr(self.0) };
        for x in s.to_u16_slice() {
            if let Ok(c) = Char16::try_from(*x) {
                write!(fmt, "{}", c)?;
            }
        }

        Ok(())
    }
}
