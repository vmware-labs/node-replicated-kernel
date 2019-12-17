//! Code to handle the loading of OS ELF modules from the UEFI file system.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;
use core::slice;

use uefi::prelude::*;
use uefi::proto::media::file::*;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::MemoryType;
use uefi::{CStr16, Char16};
use x86::bits64::paging::BASE_PAGE_SIZE;

use crate::allocate_pages;
use crate::kernel::MODULE;
use crate::kernel::{paddr_to_kernel_vaddr, paddr_to_uefi_vaddr};
use crate::round_up;
use crate::{KernelArgs, Module};

/// Trying to get the file handle for the kernel binary.
fn locate_binary(st: &SystemTable<Boot>, name: &str) -> RegularFile {
    let fhandle = st
        .boot_services()
        .locate_protocol::<SimpleFileSystem>()
        .expect_success("Don't have SimpleFileSystem support");
    let fhandle = unsafe { &mut *fhandle.get() };
    let mut root_file = fhandle.open_volume().expect_success("Can't open volume");

    // Look for the given binary name in the root folder of our EFI partition
    // in our case this is `target/x86_64-uefi/debug/esp/`
    // whereas the esp dir gets mounted with qemu using
    // `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
    let binary_file = root_file
        .open(
            format!("\\{}", name).as_str(),
            FileMode::Read,
            FileAttribute::READ_ONLY,
        )
        .expect_success("Unable to locate binary")
        .into_type()
        .expect_success("Can't cast it to a file common type??");

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
        .expect_success("Seek to the end of kernel");
    let file_size = file
        .get_position()
        .expect_success("Couldn't determine binary size") as usize;
    file.set_position(0)
        .expect_success("Reset file handle position failed");

    file_size
}

/// Load a binary from the UEFI FAT partition, and return
/// a slice to the data in memory along with a Module struct
/// that can be passed to the kernel.
pub fn load_binary_into_memory(st: &SystemTable<Boot>, name: &str) -> (Module, &'static mut [u8]) {
    // Get the binary, this should be a plain old
    // ELF executable.
    let mut module_file = locate_binary(&st, name);
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
        .expect_success("Can't read the module file");

    (
        Module::new(
            name,
            (paddr_to_kernel_vaddr(module_base_paddr), module_size),
        ),
        module_blob,
    )
}

/// Walk through the given directory of the UEFI partition
/// and return all files we find in that directory as
/// a list tuples (filename, module).
///
/// Does not recurse into subdirectories.
pub fn load_modules(st: &SystemTable<Boot>, dir_name: &str) -> Vec<(String, Module)> {
    let fhandle = st
        .boot_services()
        .locate_protocol::<SimpleFileSystem>()
        .expect_success("Don't have SimpleFileSystem support");
    let fhandle = unsafe { &mut *fhandle.get() };
    let mut root_file = fhandle.open_volume().expect_success("Can't open volume");

    // Look for the given binary name in the root folder of our EFI partition
    // in our case this is `target/x86_64-uefi/debug/esp/`
    // whereas the esp dir gets mounted with qemu using
    // `-drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp`
    let directory = root_file
        .open(dir_name, FileMode::Read, FileAttribute::READ_ONLY)
        .expect_success("Unable to locate binary")
        .into_type()
        .expect_success("Can't cast it to a file common type??");
    debug!("Opened the directory {}", dir_name);

    let mut dir_handle: Directory = match directory {
        FileType::Regular(_) => panic!("Root directory was a regular file?"),
        FileType::Dir(directory) => directory,
    };

    // We have capacity for 32 modules if you want to increase this
    // also change `modules` in KernelArgs.
    let mut modules = Vec::with_capacity(KernelArgs::MAX_MODULES);

    for _m in 0..KernelArgs::MAX_MODULES {
        const MAX_FILE_INFO_SIZE: usize = 256;
        let mut buffer: &mut [u8] = &mut [0u8; MAX_FILE_INFO_SIZE];

        match dir_handle.read_entry(&mut buffer) {
            Ok(completion) => {
                if let Some(file_info) = completion.unwrap() {
                    let file_name_16 = DCStr16(file_info.file_name().as_ptr());
                    if !file_info.attribute().contains(FileAttribute::DIRECTORY) {
                        let name_string: String = file_name_16.into();
                        if name_string != "kernel" && name_string.len() < Module::MAX_NAME_LEN {
                            let (module, _) = load_binary_into_memory(st, name_string.as_str());
                            modules.push((name_string, module));
                        } else if name_string != "kernel" {
                            // Ignore the kernel binary, it's loaded separately because it needs
                            // to be relocated too
                        } else if name_string.len() >= Module::MAX_NAME_LEN {
                            // Ignore modules with long name (since they would be truncated in Module)
                            // if you want to change this increase `Module::MAX_NAME_LEN`
                        }
                    } else {
                        // Ignore directory entries
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
