// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Functions to interact/modify process state

use log::{error, info};

use crate::rumprt::{c_int, c_void, pid_t};

/// The execve() system call transforms the calling process into a new
/// process. The new process is constructed from an ordinary file, whose
/// name is pointed to by path, called the new process file.
#[no_mangle]
pub unsafe extern "C" fn execve() {
    unreachable!("execve");
}

/// Exits the current program.
#[no_mangle]
pub unsafe extern "C" fn _exit(exit_val: c_int) {
    extern "C" {
        fn pthread_exit(ptr: *mut c_void);
    }
    if exit_val > 0 {
        error!("===> Program error, exit with {}", exit_val);
    } else {
        info!("===> Program exited successfully");
    }

    pthread_exit(exit_val as *mut c_void);
}

/// Forks the process.
#[no_mangle]
pub unsafe extern "C" fn __fork() -> c_int {
    info!("__fork called, not supported");
    crate::rumprt::errno::ENOTSUP
}

#[no_mangle]
pub unsafe extern "C" fn __vfork14() -> c_int {
    error!("__vfork14 called, not supported");
    crate::rumprt::errno::ENOTSUP
}

/// Returns information describing the resources used by the current process,
/// or all its terminated child processes.
#[no_mangle]
pub unsafe extern "C" fn __getrusage50() {
    unreachable!("__getrusage50");
}

/// The kill function sends the signal given by sig to pid,
/// a process or a group of processes.
#[no_mangle]
pub unsafe extern "C" fn kill(pid: pid_t, signal: c_int) {
    unreachable!("kill pid: {} -> sig:{}", pid, signal);
}
