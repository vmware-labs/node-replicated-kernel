// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{unsafe_abomonate, Abomonation};
use core::convert::TryInto;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
pub enum RPCError {
    // RPC
    MissingData,
    ExtraData,
    TransportError,
    MalformedResponse,
    MalformedRequest,
    InternalError,
    DuplicateRPCType,
    NoHandlerForRPCType,
    ClientInitializationError,
    ClientConnectError,
    ServerListenError,
    MemoryAllocationError,
    RegistrationError,
}
unsafe_abomonate!(RPCError);

// TODO(efficiency): type could probably be u8, but this seems easier for alignment w/ DCM?
pub type RPCType = u64;
pub const RPC_TYPE_CONNECT: u64 = 0u64;

#[derive(Debug, Default)]
#[repr(C)]
pub struct RPCHeader {
    pub msg_type: RPCType,
    pub msg_len: u64,
}

pub const HDR_LEN: usize = core::mem::size_of::<RPCHeader>();

impl RPCHeader {
    /// # Safety
    /// - `self` must be valid RPCHeader
    #[inline(always)]
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; HDR_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const RPCHeader) as *mut u8, HDR_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid RPCHeader
    #[inline(always)]
    pub unsafe fn as_bytes(&self) -> &[u8; HDR_LEN] {
        ::core::slice::from_raw_parts((self as *const RPCHeader) as *const u8, HDR_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}
