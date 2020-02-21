//! Necessary runtime support for apps that want to link with/use libc.

use alloc::vec;
use core::ptr;

use log::{debug, info, Level};

use super::prt::{lwpctl, rumprun_lwp};
use super::{c_char, c_int};

pub mod error;
pub mod mem;
pub mod message_queue;
pub mod process;
pub mod scheduler;
pub mod signals;
pub mod tls;
pub mod unsupported;

use tls::initialize_tls;

/// A pointer to the environment variables.
#[no_mangle]
pub static mut environ: *mut *const i8 = ptr::null_mut();

/// The following structure is found at the top of the user stack of each
/// user process. The ps program uses it to locate argv and environment
/// strings. Programs that wish ps to display other information may modify
/// it; normally ps_argvstr points to argv[0], and ps_nargvstr is the same
/// as the program's argc. The fields ps_envstr and ps_nenvstr are the
/// equivalent for the environment.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PsStrings {
    pub ps_argvstr: *mut *mut c_char,
    pub ps_nargvstr: c_int,
    pub ps_envstr: *mut *mut c_char,
    pub ps_nenvstr: c_int,
}

/// An instance of PsStrings.
static mut PS_STRINGS: PsStrings = PsStrings {
    ps_argvstr: ptr::null_mut(),
    ps_nargvstr: 0,
    ps_envstr: ptr::null_mut(),
    ps_nenvstr: 0,
};

/// ELF64 word (32 bits)
pub type Elf64Word = u32;

/// ELF64 XWord (64 bits)
pub type Elf64Xword = u64;

/// Auxiliary Vectors
///
/// When a program is executed, it receives information from the operating system
/// about the environment in which it is operating.
/// The form of this information is a table of key-value pairs,
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Aux64Info {
    pub a_type: Elf64Word,
    pub a_v: Elf64Xword,
}

/// Marks end of array.
const AT_NULL: Elf64Word = 0;

/// Base address of the main thread stack.
const AT_STACKBASE: Elf64Word = 13;

/// Store initial information about the process.
///
/// (auxiliary table, command line arguments and environment arguments)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct InitInfo {
    pub argv_dummy: *mut c_char,
    pub env_dummy: *mut c_char,
    pub ai: [Aux64Info; 2usize],
}

/// An initial allocation for InitInfo storage.
static mut INIT_INFO: InitInfo = InitInfo {
    argv_dummy: ptr::null_mut(),
    env_dummy: ptr::null_mut(),
    ai: [
        Aux64Info {
            a_type: AT_STACKBASE,
            a_v: 0x1000_000,
        },
        Aux64Info {
            a_type: AT_NULL,
            a_v: 0,
        },
    ],
};

/// Sets up ps strings.
pub unsafe fn netbsd_userlevel_init() {
    extern "C" {
        static mut __ps_strings: *mut PsStrings;
    }

    PS_STRINGS.ps_argvstr = &mut INIT_INFO.argv_dummy;
    __ps_strings = &mut PS_STRINGS as *mut PsStrings;
}

pub fn install_vcpu_area() {
    use x86::bits64::paging::VAddr;
    let ctl = crate::syscalls::vcpu_control_area().expect("Can't read vcpu control area.");
    ctl.resume_with_upcall =
        VAddr::from(crate::upcalls::upcall_while_enabled as *const fn() as u64);
}

/// Entry point for libc.
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main() {
    extern "C" {
        fn main();
    }

    main();

    unreachable!("return from main() in __libc_start_main?");
}

#[no_mangle]
pub extern "C" fn main() {
    use cstr_core::CStr;

    #[repr(C)]
    struct tmpfs_args {
        ta_version: u64, // c_int
        /* Size counters. */
        ta_nodes_max: u64, // ino_t			ta_nodes_max;
        ta_size_max: i64,  // off_t			ta_size_max;
        /* Root node attributes. */
        ta_root_uid: u32,  // uid_t			ta_root_uid;
        ta_root_gid: u32,  // gid_t			ta_root_gid;
        ta_root_mode: u32, // mode_t		ta_root_mode;
    }

    extern "C" {
        static __init_array_start: extern "C" fn();
        static __init_array_end: extern "C" fn();

        fn rump_boot_setsigmodel(sig: usize);
        fn rump_init() -> u64;
        fn _libc_init();
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);
        fn rumprun_main1(argc: c_int, argv: *const *const i8);
    }

    unsafe {
        log::set_logger(&crate::writer::LOGGER)
            .map(|()| log::set_max_level(Level::Debug.to_level_filter()))
            .expect("Can't set-up logging");
    }
    debug!("Initialized logging");
    install_vcpu_area();

    let up = lineup::Upcalls {
        curlwp: super::rumpkern_curlwp,
        deschedule: super::rumpkern_unsched,
        schedule: super::rumpkern_sched,
    };

    let mut scheduler = lineup::Scheduler::new(up);
    scheduler.spawn(
        32 * 4096,
        |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(0);
            let ri = rump_init();
            assert_eq!(ri, 0);
            info!("rump_init({}) done in {:?}", ri, start.elapsed());

            const TMPFS_ARGS_VERSION: u64 = 1;

            let tfsa = tmpfs_args {
                ta_version: TMPFS_ARGS_VERSION,
                ta_nodes_max: 0,
                ta_size_max: 1 * 1024 * 1024,
                ta_root_uid: 0,
                ta_root_gid: 0,
                ta_root_mode: 0o1777,
            };

            let path = CStr::from_bytes_with_nul(b"/tmp\0");
            let tmpfs_ident = CStr::from_bytes_with_nul(b"tmpfs\0");
            info!("mounting tmpfs");

            let _r = mount(
                tmpfs_ident.unwrap().as_ptr(),
                path.unwrap().as_ptr(),
                0,
                &tfsa,
                core::mem::size_of::<tmpfs_args>(),
            );

            let tls_buffer: *mut u8 = initialize_tls();
            x86::current::segmentation::wrfsbase(tls_buffer as u64);
            info!(
                "tls buffer set to {:#x}",
                x86::current::segmentation::rdfsbase()
            );

            // Set up a garbage environment
            let mut c_environ = vec![
                CStr::from_bytes_with_nul_unchecked(b"PTHREAD_STACKSIZE=32000\0").as_ptr(),
                ptr::null_mut(),
            ];
            super::crt::environ = c_environ.as_mut_ptr();

            // Set up the lwp pointer stuff
            let t = lineup::tls::Environment::thread();
            let mut mainthread = rumprun_lwp {
                id: 1,
                rl_lwpctl: lwpctl {
                    lc_curcpu: 0,
                    lc_pctr: 0,
                },
            };
            t.rumprun_lwp = &mut mainthread as *mut _ as *mut u64;

            // do the _netbsd_userlevel_init stuff:
            netbsd_userlevel_init();
            _libc_init();
            {
                let mut f = &__init_array_start as *const _;
                while f < &__init_array_end {
                    (*f)();
                    f = f.offset(1);
                }
            }

            // Construct silly arguments
            let c_args = vec![
                CStr::from_bytes_with_nul_unchecked(b"redis-server.bin\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"redis-server.bin\0").as_ptr(),
            ];

            rumprun_main1(0, c_args.as_ptr());
        },
        core::ptr::null_mut(),
    );

    scheduler.run();
    core::mem::forget(scheduler);
    unreachable!("rump main returned?");
}

// # TODO
// This should be unnecessary?
// comes from `/usr/lib/gcc/x86_64-linux-gnu/7/../../../x86_64-linux-gnu/crt1.o`
#[no_mangle]
pub unsafe extern "C" fn __libc_csu_fini() {
    unimplemented!("__libc_csu_fini");
}

// # TODO
// This should be unnecessary?
// comes from `/usr/lib/gcc/x86_64-linux-gnu/7/../../../x86_64-linux-gnu/crt1.o`
#[no_mangle]
pub unsafe extern "C" fn __libc_csu_init() {
    unimplemented!("__libc_csu_init");
}
