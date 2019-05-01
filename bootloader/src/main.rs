#![no_std]
#![no_main]
#![feature(slice_patterns)]
#![feature(alloc)]
#![feature(asm, global_asm)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

extern crate uefi;
extern crate uefi_exts;
extern crate uefi_services;

extern crate elfloader;
extern crate x86;

use uefi::prelude::*;

use uefi::proto::media::fs::SimpleFileSystem;
use uefi_exts::BootServicesExt;

use x86::bits64::paging::*;

use uefi::table::boot::{AllocateType, BootServices, MemoryDescriptor, MemoryType};

use crate::alloc::vec::Vec;
use core::mem;
use core::mem::transmute;
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

global_asm!(include_str!("switch.S"));
extern "C" {
    fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: &SystemTable<Boot>);
}

#[no_mangle]
pub extern "C" fn uefi_start(_handle: uefi::Handle, st: SystemTable<Boot>) -> Status {
    uefi_services::init(&st);
    info!("UEFI Bootloader");
    check_revision(st.uefi_revision());

    /// Get The kernel binary
    {
        if let Ok(mut fhandle) = st.boot_services().locate_protocol::<SimpleFileSystem>() {
            use uefi::proto::media::file::*;

            //info!("- File System Handle: {:?}", fhandle);
            let mut fhandle = fhandle.unwrap();
            let mut root_file = unsafe { (*fhandle.get()).open_volume().ok().unwrap() }.unwrap();

            let kernel_binary = "kernel";
            let mut kernel_file = root_file
                .open(
                    format!("\\{}", kernel_binary).as_str(),
                    FileMode::Read,
                    FileAttribute::READ_ONLY,
                )
                .expect_success("Can't open kernel binary")
                .into_type()
                .expect_success("Can't put in a type");

            let mut kernel_file: RegularFile = match kernel_file {
                FileType::Regular(t) => t,
                _ => panic!("not a regular file"),
            };
            info!("found the file");

            kernel_file
                .set_position(0xFFFFFFFFFFFFFFFF)
                .expect("Seek to end of kernel");
            let mut kernel_size = kernel_file
                .get_position()
                .expect("Get size of kernel")
                .unwrap() as usize;
            kernel_file.set_position(0).expect("Set position failed");
            info!("seek ok");

            let mut kernel_blob = alloc::vec::Vec::with_capacity(kernel_size);
            info!("vec reserved size = {}", kernel_size);
            kernel_blob.resize(kernel_size, 0);
            info!("vec allocated");
            kernel_file
                .read(kernel_blob.as_mut_slice())
                .expect("Can't read the kernel");
            info!("file read to vec");

            let pml4: PAddr = PAddr::from_u64(VSpace::allocate_one_page() as u64);
            let pml4_table = unsafe { transmute::<VAddr, &mut PML4>(paddr_to_kernel_vaddr(pml4)) };

            let mut kernel = Kernel {
                mapping: Vec::new(),
                vspace: VSpace { pml4: pml4_table },
            };

            info!("Loading kernel size {}", kernel_blob.len());
            let binary = elfloader::ElfBinary::new(kernel_binary, kernel_blob.as_slice()).unwrap();
            info!("trying to load kernel binary");

            binary.load(&mut kernel);

            info!("loaded... now jump to 0x{:x}", binary.entry_point());

            kernel.vspace.map_identity(
                VAddr::from(0x1000usize),
                VAddr::from(0x90000000usize + 65536 * 4096),
            );

            // print current memory map
            //let st:&'static SystemTable = system_table();

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
                //setup::dump_table(pml4_table);

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
                info!("before flushing");


                info!("rsp is {:x}", x86::current::registers::rsp());
                info!(
                    "Switch to kernel stack at {:x}",
                    num as usize + 64 * BASE_PAGE_SIZE
                );


                info!(
                    "about to jump {:p}",
                    (binary.entry_point() + setup::KERNEL_OFFSET as u64) as *const u64
                );
                x86::tlb::flush_all();

                let addr = (binary.entry_point() + setup::KERNEL_OFFSET as u64);
                //assert_eq!(addr, 0x800000022720);

                unsafe {
                    let ptr = 0x3e0ef000 as *const u8;
                    let slice = core::slice::from_raw_parts(0x3e0ef000 as *const u8, 32);
                    info!("text section of kernel at paddr is {:?}", slice);


                    let ptr = setup::KERNEL_OFFSET as *const u8;
                    info!("base ptr addr is {:p}", ptr);
                    let slice = core::slice::from_raw_parts(addr as *const u8, 32);
                    info!("start fn of kernel is {:?}", slice);
                }
                // INFO: start fn of kernel is [85, 72, 137, 229, 72, 129, 236, 160, 13, 0, 0, 72, 137, 189, 88, 244, 255, 255, 72, 137, 181, 96, 244, 255, 255, 232, 34, 224, 6, 0, 72, 141]
                /*
                0000000000022720 <_start>:
                   22720:       55                      push   %rbp
                   22721:       48 89 e5                mov    %rsp,%rbp
                   22724:       48 81 ec a0 0d 00 00    sub    $0xda0,%rsp
                   2272b:       48 89 bd 58 f4 ff ff    mov    %rdi,-0xba8(%rbp)
                   22732:       48 89 b5 60 f4 ff ff    mov    %rsi,-0xba0(%rbp)
                   22739:       e8 22 e0 06 00          callq  90760 <_ZN7klogger12WriterNoDrop3get17hc95c0dea5a93c64cE>
                   2273e:       48 8d 05 db 89 29 00    lea    0x2989db(%rip),%rax        # 2bb120 <GCC_except_table21+0x202030>
                   22745:       48 8d 0d ac 87 08 00    lea    0x887ac(%rip),%rcx        # aaef8 <str.2+0xa8>
                   2274c:       31 d2                   xor    %edx,%edx
                   2274e:       41 89 d0                mov    %edx,%r8d
                   22751:       48 8d bd 70 f4 ff ff    lea    -0xb90(%rbp),%rdi
                   22758:       48 89 c6                mov    %rax,%rsi
                   2275b:       ba 01 00 00 00          mov    $0x1,%edx
                   22760:       e8 4b 52 00 00          callq  279b0 <_ZN4core3fmt9Arguments6new_v117h24e3fb48a6e79896E>
                   22765:       48 8d bd 68 f4 ff ff    lea    -0xb98(%rbp),%rdi
                */
                jump_to_kernel((num as usize + 64 * BASE_PAGE_SIZE) as u64, addr, &st);
                info!("returned?");
            }

        } else {
            error!("Failed to retrieve the list of handles");
        }
    }

    uefi::Status(0)
}

fn check_revision(rev: uefi::table::Revision) {
    let (major, minor) = (rev.major(), rev.minor());
    info!("UEFI {}.{}", major, minor);
    assert!(major >= 2, "Running on an old, unsupported version of UEFI");
    assert!(
        minor >= 30,
        "Old version of UEFI 2, some features might not be available."
    );
}
