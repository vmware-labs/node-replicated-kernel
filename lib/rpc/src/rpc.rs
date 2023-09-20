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

pub type RPCType = u8;
pub const RPC_TYPE_CONNECT: u8 = 0u8;
pub const MAX_RPC_TYPE: usize = 256; // Max # of RPC types
pub type MsgId = u8;
pub const MAX_INFLIGHT_MSGS: usize = 256; // Max # of MsgIds
pub type MsgLen = u16;

// TODO: remove copy/clone
#[derive(Debug, Default, Copy, Clone)]
#[repr(C, packed)]
pub struct RPCHeader {
    pub msg_id: MsgId,
    pub msg_type: RPCType,
    pub msg_len: MsgLen,
}
pub const HDR_LEN: usize = core::mem::size_of::<RPCHeader>();

impl RPCHeader {
    // TODO: remove copy from??
    pub fn copy_from(&mut self, from: RPCHeader) {
        self.msg_id = from.msg_id;
        self.msg_type = from.msg_type;
        self.msg_len = from.msg_len;
    }

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

    /// # Safety
    /// - bytes must be HDR_LEN long.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> RPCHeader {
        RPCHeader {
            msg_id: bytes[0],
            msg_type: bytes[1],
            // TODO: this is a bit architecture specific
            msg_len: ((bytes[3] as u16) << 8) | (bytes[2] as u16),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::RPCHeader;

    #[ignore]
    #[test]
    fn test_hdr_serialization() {
        let orig_id = 5;
        let orig_type = 10;
        let orig_len = 251;
        let hdr = RPCHeader {
            msg_id: orig_id,
            msg_type: orig_type,
            msg_len: orig_len,
        };

        let bytes = unsafe { hdr.as_bytes() };
        let hdr2 = RPCHeader::from_bytes(bytes);

        let new_id = hdr2.msg_id;
        let new_type = hdr2.msg_type;
        let new_len = hdr2.msg_len;

        assert_eq!(orig_id, new_id);
        assert_eq!(orig_type, new_type);
        assert_eq!(orig_len, new_len);
    }
}
