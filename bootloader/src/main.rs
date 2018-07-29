#![no_std]
#![no_main]
#![feature(slice_patterns)]
#![feature(alloc)]
#![feature(asm)]

extern crate uefi;
extern crate uefi_services;
extern crate uefi_utils;

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;
extern crate elfloader;

mod boot;
mod proto;
mod ucs2;

use uefi::table;
use uefi::{Handle, Status};

use elfloader::elf;

struct Kernel {}

impl elfloader::ElfLoader for Kernel {
    /// Makes sure the process vspace is backed for the region reported by the elf loader.
    fn allocate(&mut self, base: usize, size: usize, flags: elf::ProgFlag) {
        info!("allocate: 0x{:x} -- 0x{:x}", base, base + size);
    }

    /// Load a region of bytes into the virtual address space of the process.
    /// XXX: Report error if that region is not backed by memory (i.e., allocate was not called).
    fn load(&mut self, destination: usize, region: &'static [u8]) {
        info!(
            "load: 0x{:x} -- 0x{:x}",
            destination,
            destination + region.len()
        );
    }
}

#[no_mangle]
pub extern "C" fn uefi_start(_handle: Handle, st: &'static table::SystemTable) -> Status {
    uefi_services::init(st);

    let stdout = st.stdout();
    let bt = st.boot;

    macro_rules! timeout {
        ($msg:expr, $seconds:expr) => {
            for i in 0..$seconds {
                let (_, row) = stdout.get_cursor_position();
                info!($msg, $seconds - i);
                stdout.set_cursor_position(0, row).unwrap();

                bt.stall(1_000_000);
            }

            info!($msg, 0);
        };
    }

    let map_sz = bt.memory_map_size();
    info!("map_sz is : {} in pages {}", map_sz, map_sz / 4096);
    let mut buffer = alloc::vec::Vec::with_capacity(map_sz + 4096 * 2);
    buffer.resize(map_sz + 4096 * 2, 0);
    let (key, mut desc_iter) = bt
        .memory_map(buffer.as_mut_slice())
        .expect("Retrieve memory map");
    info!("Memory map key {:?}", key);
    let mut all_conv_mem_pages = 0;
    for (idx, mminfo) in desc_iter
        .filter(|mm| mm.ty == uefi::table::boot::MemoryType::Conventional)
        .enumerate()
    {
        info!("memory descriptor: {:?}", mminfo.page_count);
        all_conv_mem_pages += mminfo.page_count;
    }
    loop {}

    // Reset the console.
    {
        stdout.reset(false).expect("Failed to reset stdout");
    }

    // Switch to the maximum supported graphics mode.
    {
        let best_mode = stdout.modes().last().unwrap();
        stdout
            .set_mode(best_mode)
            .expect("Failed to change graphics mode");
    }

    // Set a new color, and paint the background with it.
    {
        use uefi::proto::console::text::Color;
        stdout
            .set_color(Color::White, Color::Blue)
            .expect("Failed to change console color");
        stdout.clear().expect("Failed to clear screen");
    }

    // Move the cursor.
    {
        stdout.enable_cursor(true).expect("Failed to enable cursor");
        stdout
            .set_cursor_position(24, 0)
            .expect("Failed to move cursor");
        stdout
            .enable_cursor(false)
            .expect("Failed to enable cursor");

        // This will make this `info!` line be (somewhat) centered.
        info!("# uefi-rs test runner");
    }

    {
        let revision = st.uefi_revision();
        let (major, minor) = (revision.major(), revision.minor());

        info!("UEFI {}.{}.{}", major, minor / 10, minor % 10);
    }

    info!("");

    // Print all modes.
    for (index, mode) in stdout.modes().enumerate() {
        info!(
            "Graphics mode #{}: {} rows by {} columns",
            index,
            mode.rows(),
            mode.columns()
        );
    }

    info!("");

    /// Get The kernel binary
    {
        if let Some(mut fhandle) =
            uefi_utils::proto::find_protocol::<uefi::proto::media::SimpleFileSystem>()
        {
            use uefi::proto::media::FileAttribute;
            use uefi::proto::media::FileMode;

            info!("- File System Handle: {:?}", fhandle);
            let mut root_file = unsafe { fhandle.as_mut().open_volume().ok().unwrap() };

            let kernel_binary = "tup";
            let mut kernel_file = root_file
                .open(
                    format!("\\{}", kernel_binary).as_str(),
                    FileMode::READ,
                    FileAttribute::NONE,
                )
                .expect("Can't open kernel binary");

            kernel_file
                .set_position(0xFFFFFFFFFFFFFFFF)
                .expect("Seek to end of kernel");
            let kernel_size = kernel_file.get_position().expect("Get size of kernel") as usize;
            kernel_file.set_position(0).expect("Set position failed");

            let mut kernel_blob = alloc::vec::Vec::with_capacity(kernel_size);
            kernel_blob.resize(kernel_size, 0);
            kernel_file
                .read(kernel_blob.as_mut_slice())
                .expect("Can't read the kernel");

            let mut kernel = Kernel {};
            info!("Loading kernel size {}", kernel_blob.len());
            elfloader::ElfBinary::new(kernel_binary, kernel_blob.as_slice()).map(|e| {
                info!("trying to load kernel binary");
                e.load(&mut kernel);
                info!("loaded...");

                //p.start(0x4000f0);
            });
        } else {
            error!("Failed to retrieve the list of handles");
        }
    }

    loop {}
    timeout!("Testing complete, shutting down in {} second(s)...", 3);
    let rt = st.runtime;
    rt.reset(table::runtime::ResetType::Shutdown, Status::Success, None);
}
