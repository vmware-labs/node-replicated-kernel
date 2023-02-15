// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Necessary runtime support for apps that want to link with/use libc.

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use cstr_core::{CStr, CString};
use log::{debug, error, info, Level};
use x86::current::paging::VAddr;

use super::{c_char, c_int};

use crate::syscalls::Fs;
use kpi::io::*;

pub mod error;
pub mod mem;
pub mod message_queue;
pub mod process;
pub mod scheduler;
pub mod signals;
pub mod tls;
pub mod unsupported;

pub const RUMP_RFFDG: c_int = 0x01;

use crate::rumprt::{c_ulong, c_void};
#[allow(non_camel_case_types)]
type pthread_t = c_ulong;

/// A pointer to the environment variables.
#[no_mangle]
pub static mut environ: *mut *const i8 = ptr::null_mut();

static mut main_argc: i32 = 0;
static mut main_argv: *const *const i8 = ptr::null();

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
#[repr(C)]
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
    let ctl = crate::syscalls::Process::vcpu_control_area().expect("Can't read vcpu control area.");
    ctl.resume_with_upcall =
        VAddr::from(crate::upcalls::upcall_while_enabled as *const fn() as u64);

    let upcall_begin_rip = crate::upcalls::resume as *const fn() as u64;
    extern "C" {
        fn resume_end();
    }
    let upcall_end_rip = resume_end as *const fn() as u64;

    info!(
        "upcall_begin_rip {:#x} upcall_end_rip {:#x}",
        upcall_begin_rip, upcall_end_rip
    );

    // We assume: functions compiled in upcall.rs appear in consecutive order in the binary
    // (as they are listed in the file)
    // and that there are no other symbols (from other files) added inbetween...
    // I realize this is asking for much.
    assert!(
        upcall_begin_rip < upcall_end_rip,
        "Beginning is before the end?"
    );
    assert!(
        upcall_end_rip - upcall_begin_rip < 0x1000,
        "Unusually large code footprint of resume()?"
    );
    ctl.pc_disabled = (VAddr::from(upcall_begin_rip), VAddr::from(upcall_end_rip));
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

pub static READY_TO_RUMBLE: AtomicBool = AtomicBool::new(false);

extern "C" fn ready() {
    info!("rump_init ready callback");
    READY_TO_RUMBLE.store(true, Ordering::SeqCst);
}

extern "C" {
    fn rump_pub_lwproc_curlwp() -> *mut c_void;
    fn rump_pub_lwproc_switch(lwp: *const c_void);
    fn rump_pub_lwproc_newlwp(pid: c_int) -> c_int;
    fn rump_pub_lwproc_rfork(flags: c_int) -> c_int;
    fn rumprun_main1(argc: c_int, argv: *const *const i8);
    fn pthread_create(
        native: *mut pthread_t,
        attr: *const c_void,
        f: extern "C" fn(*mut c_void) -> *mut c_void,
        value: *mut c_void,
    ) -> c_int;
}

extern "C" fn mainstarter(lwp: *mut c_void) -> *mut c_void {
    unsafe {
        rump_pub_lwproc_switch(lwp);

        rumprun_main1(main_argc, main_argv);
        ptr::null_mut()
    }
}

unsafe fn setup_process() {
    let pipein: c_int = -1;
    let newpipein: c_int = -1;

    if !rump_pub_lwproc_curlwp().is_null() {
        panic!("setup_process needs support for non-implicit callers");
    }

    rump_pub_lwproc_rfork(RUMP_RFFDG);

    let lwp = rump_pub_lwproc_curlwp();
    error!("NYI: pipe stuff");
    rump_pub_lwproc_switch(ptr::null_mut());

    let mut ptid: pthread_t = 0;
    if pthread_create(&mut ptid as *mut pthread_t, ptr::null(), mainstarter, lwp) != 0 {
        panic!("running main fn failed\n");
    }
}

#[no_mangle]
pub extern "C" fn main() {
    use lineup::tls2::SchedulerControlBlock;
    let scb: SchedulerControlBlock = SchedulerControlBlock::new(0);
    unsafe { scb.preinstall() };

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
        fn rump_init(fnptr: extern "C" fn()) -> u64;
        fn rump_pub_etfs_register(key: *const i8, hostpath: *const i8, ftype: i32) -> i32;
        fn rump_pub_netconfig_dhcp_ipv4_oneshot(iface: *const i8) -> i64;
        fn _libc_init();
        fn mount(typ: *const i8, path: *const i8, n: u64, args: *const tmpfs_args, argsize: usize);
    }

    unsafe {
        log::set_logger(&crate::writer::LOGGER)
            .map(|()| log::set_max_level(Level::Error.to_level_filter()))
            .expect("Can't set-up logging");
    }
    debug!("Initialized logging");
    install_vcpu_area();

    let hwthreads = crate::syscalls::System::threads().expect("Can't get system topology");
    let mut maximum = 1; // We already have core 0

    let pinfo = crate::syscalls::Process::process_info().expect("Can't read process info");

    let ncores: Option<usize> = pinfo.cmdline.parse().ok();
    for hwthread in hwthreads.iter().take(ncores.unwrap_or(hwthreads.len())) {
        if hwthread.id != 0 {
            info!("request core {:?}", hwthread);
            match crate::syscalls::Process::request_core(
                hwthread.id,
                VAddr::from(crate::upcalls::upcall_while_enabled as *const fn() as u64),
            ) {
                Ok(_) => {
                    maximum += 1;
                    continue;
                }
                Err(e) => {
                    error!("Can't spawn on {:?}: {:?}", hwthread.id, e);
                    break;
                }
            }
        }
    }

    // Split app args into individual parts
    let parsed_args: Vec<&str> = pinfo.app_cmdline.rsplit(' ').collect();
    // Necessary to maintain references to the arg CStrings
    let mut ref_args: Vec<CString> = Vec::with_capacity(parsed_args.len() + 1);
    ref_args.push(CString::new("some.bin").unwrap()); // First arg is always bin name

    for i in 0..parsed_args.len() {
        ref_args.push(CString::new(parsed_args[i]).unwrap());
    }

    let c_args: Vec<*const i8> = ref_args
        .into_iter()
        .map(|x| x.into_raw() as *const i8)
        .collect();
    unsafe {
        main_argv = c_args.as_ptr();
        main_argc = c_args.len() as i32;
    }

    let scheduler = &crate::upcalls::PROCESS_SCHEDULER;
    scheduler.spawn(
        64 * 4096,
        move |_yielder| unsafe {
            let start = rawtime::Instant::now();
            rump_boot_setsigmodel(0);
            let ri = rump_init(ready);
            error!("rump_init({}) done in {:?}", ri, start.elapsed());
            assert_eq!(ri, 0);

            // This is used by leveldb only.
            if parsed_args.contains(&"--benchmarks=fillseq,readrandom") {
                let key2 = CStr::from_bytes_with_nul(b"/tmp/leveldbtest-0\0");
                let hostpath = CStr::from_bytes_with_nul(b"/\0");
                let etfs_ret =
                    rump_pub_etfs_register(key2.unwrap().as_ptr(), hostpath.unwrap().as_ptr(), 4);
                error!("result of pub_etfs_register? {}\n", etfs_ret);
                assert_eq!(etfs_ret, 0);
                Fs::mkdir_simple("//dbbench", FileModes::S_IRWXU)
                    .expect("Unable to create directory");
            } else {
                const TMPFS_ARGS_VERSION: u64 = 1;

                let tfsa = tmpfs_args {
                    ta_version: TMPFS_ARGS_VERSION,
                    ta_nodes_max: 0,
                    ta_size_max: 256 * 1024 * 1024,
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
            }

            #[cfg(feature = "virtio")]
            let nic_model = b"vioif0\0";
            #[cfg(not(feature = "virtio"))]
            let nic_model = b"wm0\0";
            let iface = CStr::from_bytes_with_nul(nic_model);

            info!("before rump_pub_netconfig_dhcp_ipv4_oneshot");

            let r = rump_pub_netconfig_dhcp_ipv4_oneshot(iface.unwrap().as_ptr());
            assert_eq!(r, 0, "rump_pub_netconfig_dhcp_ipv4_oneshot");
            info!(
                "rump_pub_netconfig_dhcp_ipv4_oneshot done in {:?}",
                start.elapsed()
            );

            // Set up a garbage environment
            let mut c_environ = vec![
                CStr::from_bytes_with_nul_unchecked(b"PTHREAD_STACKSIZE=64000\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"OMP_NUM_THREADS=80\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"OMP_DYNAMIC=FALSE\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"GOMP_DEBUG=1\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"OMP_DISPLAY_ENV=TRUE\0").as_ptr(),
                CStr::from_bytes_with_nul_unchecked(b"GOMP_SPINCOUNT=INFINITY\0").as_ptr(),
                ptr::null_mut(),
            ];
            super::crt::environ = c_environ.as_mut_ptr();

            // Set up the lwp pointer stuff
            super::prt::rumprun_lwp_init(ncores.unwrap_or(1));

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

            // Give all threads a chance to run, and ensure that the main
            // thread has gone through a context switch
            lineup::tls2::Environment::thread().relinquish();
            setup_process();

            loop {
                lineup::tls2::Environment::thread().block()
            }
        },
        core::ptr::null_mut(),
        0,
        None,
    );

    loop {
        scheduler.run(&scb);
    }

    //core::mem::forget(scheduler);
    //unreachable!("rump main returned?");
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
