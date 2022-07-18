// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use lazy_static::lazy_static;
use log::{debug, error};
use rpc::rpc::*;

use crate::error::KError;

// Struct used to encapulate a system call result
#[derive(Debug)]
pub(crate) struct SyscallRes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(SyscallRes: ret);
pub(crate) const SYSCALL_RES_SIZE: u64 = core::mem::size_of::<SyscallRes>() as u64;

// Below are utility functions for working with SyscallRes

#[inline(always)]
pub(crate) fn construct_error_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    err: RPCError,
) -> Result<(), RPCError> {
    let res = SyscallRes { ret: Err(err) };
    construct_ret(hdr, payload, res)
}

#[inline(always)]
pub(crate) fn construct_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    res: SyscallRes,
) -> Result<(), RPCError> {
    construct_ret_extra_data(hdr, payload, res, 0)
}

#[inline(always)]
pub(crate) fn construct_ret_extra_data(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    res: SyscallRes,
    additional_data_len: u64,
) -> Result<(), RPCError> {
    // Encode payload in buffer
    unsafe { encode(&res, &mut payload) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = SYSCALL_RES_SIZE + additional_data_len;
    Ok(())
}

#[inline(always)]
pub(crate) fn convert_return(
    cnrfs_ret: Result<(u64, u64), KError>,
) -> Result<(u64, u64), RPCError> {
    match cnrfs_ret {
        Ok(ret) => Ok(ret),
        Err(err) => Err(err.into()),
    }
}
