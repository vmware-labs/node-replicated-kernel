// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! System call stubs

use crate::error::KResult;
use crate::process::UserSlice;
use crate::syscalls::{ProcessDispatch, SystemCallDispatch, SystemDispatch, VSpaceDispatch};

pub(crate) struct UnixSystemCalls;
impl crate::syscalls::CnrFsDispatch for UnixSystemCalls {}

impl SystemCallDispatch<u64> for UnixSystemCalls {}

impl SystemDispatch<u64> for UnixSystemCalls {
    fn get_hardware_threads(&self, _vbuf_base: u64, _vbuf_len: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn get_stats(&self) -> KResult<(u64, u64)> {
        todo!()
    }

    fn get_core_id(&self) -> KResult<(u64, u64)> {
        todo!()
    }
}

impl ProcessDispatch<u64> for UnixSystemCalls {
    fn log(&self, _buffer_arg: UserSlice) -> KResult<(u64, u64)> {
        todo!()
    }

    fn get_vcpu_area(&self) -> KResult<(u64, u64)> {
        todo!()
    }

    fn allocate_vector(&self, _vector: u64, _core: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn get_process_info(&self, _vaddr_buf: u64, _vaddr_buf_len: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn request_core(&self, _core_id: u64, _entry_point: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn release_core(&self, _core_id: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn allocate_physical(&self, _page_size: u64, _affinity: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn release_physical(&self, _frame_id: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn exit(&self, _code: u64) -> KResult<(u64, u64)> {
        todo!()
    }
}

impl VSpaceDispatch<u64> for UnixSystemCalls {
    fn map_mem(&self, _base: u64, _size: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn map_pmem(&self, _base: u64, _size: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn map_device(&self, _base: u64, _size: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn map_frame_id(&self, _base: u64, _frame_id: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn unmap_mem(&self, _base: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn unmap_pmem(&self, _base: u64) -> KResult<(u64, u64)> {
        todo!()
    }

    fn identify(&self, _addr: u64) -> KResult<(u64, u64)> {
        todo!()
    }
}

/// Dispatch logic for global system calls.
pub(crate) trait Arch86SystemDispatch {}

pub(crate) fn syscall_handle(function: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) {
    let status = {
        let dispatch = UnixSystemCalls;
        dispatch.handle(function, arg1, arg2, arg3, arg4, arg5)
    };

    match status {
        Ok((a1, a2)) => {
            log::info!("System call returned with: {:?} {:?}", a1, a2);
        }
        Err(status) => {
            log::warn!("System call returned with error: {:?}", status);
        }
    }
}
