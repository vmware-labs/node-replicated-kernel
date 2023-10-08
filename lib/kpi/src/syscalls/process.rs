// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Abstraction for system calls to do control the current process.

use crate::*;

use crate::process::{CoreToken, ProcessInfo};
use crate::syscall;
use crate::x86_64::VirtualCpu;

use x86::bits64::paging::VAddr;

pub struct Process;

impl Process {
    /// Request to run on `core_id` starting at `entry_point`.
    pub fn request_core(core_id: usize, entry_point: VAddr) -> Result<CoreToken, SystemCallError> {
        let (r, gtid, _eid) = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::RequestCore as u64,
                core_id as u64,
                entry_point.as_u64(),
                3
            )
        };

        if r == 0 {
            Ok(CoreToken::from(gtid))
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Request to release on `core_id` that was previously requested.
    /// This is an unsafe function and should only be called when the
    /// executor spawned on the thread has completed.
    pub fn release_core(core_id: usize) -> Result<(), SystemCallError> {
        let (r, _unused, _eid) = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::ReleaseCore as u64,
                core_id as u64,
                3
            )
        };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Print `buffer` on the console.
    pub fn print(buffer: &str) -> Result<(), SystemCallError> {
        let r = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::Log as u64,
                buffer.as_ptr() as u64,
                buffer.len(),
                1
            )
        };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Gets the VCPU memory location for the current core of the thread.
    ///
    /// This is allocated and controlled by the kernel, it doesn't move and
    /// will be valid as long as the current CPU is allocated to the process.
    pub fn vcpu_control_area() -> Result<&'static mut VirtualCpu, SystemCallError> {
        let (r, control) = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::GetVCpuArea as u64,
                2
            )
        };

        if r == 0 {
            let vaddr = VAddr::from(control);
            assert!(vaddr.is_base_page_aligned());
            let vcpu_ctl: *mut VirtualCpu = vaddr.as_mut_ptr::<VirtualCpu>();
            unsafe { Ok(&mut *vcpu_ctl) }
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Query process specific information.
    pub fn process_info() -> Result<ProcessInfo, SystemCallError> {
        let mut buf = alloc::vec![0; 256];
        let (r, len) = unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::GetProcessInfo as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                2
            )
        };

        if r == 0 {
            let len = len as usize;
            debug_assert!(len <= buf.len());
            buf.resize(len, 0);
            let static_buf = alloc::vec::Vec::leak(buf);
            let deserialized: ProcessInfo = serde_cbor::from_slice(static_buf).unwrap();
            Ok(deserialized)
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Exit the process (pass an error `code` to exit).
    pub fn exit(code: u64) -> ! {
        unsafe {
            syscall!(
                SystemCall::Process as u64,
                ProcessOperation::Exit as u64,
                code,
                1
            );

            // This stops the process and never returns:
            unreachable!()
        }
    }
}
