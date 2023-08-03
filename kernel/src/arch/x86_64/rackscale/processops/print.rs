// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use core::fmt::Debug;

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use alloc::string::String;
use core2::io::Result as IOResult;
use core2::io::Write;

use klogger::sprint;
use kpi::system::MachineId;
use rpc::rpc::*;

use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use crate::arch::serial::SerialControl;
use crate::error::{KError, KResult};
use crate::fallible_string::TryString;

#[derive(Debug)]
pub(crate) struct LogReq {
    pub mid: MachineId,
}
unsafe_abomonate!(LogReq: mid);

pub(crate) fn rpc_log(msg: String) -> KResult<(u64, u64)> {
    if let Some(print_str) = SerialControl::buffered_print_and_return(&msg) {
        // Construct request data
        let req = LogReq {
            mid: *crate::environment::MACHINE_ID,
        };
        let mut req_data = [0u8; core::mem::size_of::<LogReq>()];
        unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
            .expect("Failed to encode log request");

        // Construct result buffer and call RPC
        let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
        CLIENT_STATE.rpc_client.lock().call(
            KernelRpc::Log as RPCType,
            &[&req_data, print_str.as_ref()],
            &mut [&mut res_data],
        )?;

        // Decode and return the result
        if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
            if remaining.len() > 0 {
                log::error!("Log() RPC failed");
                Err(KError::from(RPCError::ExtraData))
            } else {
                *res
            }
        } else {
            Err(KError::from(RPCError::MalformedResponse))
        }
    } else {
        Ok((0, 0))
    }
}

// RPC Handler function for log() RPCs in the controller
pub(crate) fn handle_log(hdr: &mut RPCHeader, mut payload: &mut [u8]) -> Result<(), RPCError> {
    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<LogReq>(&mut payload) } {
        match core::str::from_utf8(
            &remaining[0..(hdr.msg_len as usize - core::mem::size_of::<LogReq>())],
        ) {
            Ok(msg_str) => log::info!("RemoteLog({}) {}", res.mid, msg_str),
            Err(e) => log::error!(
                "log: invalid UTF-8 string: {:?}",
                &payload[0..hdr.msg_len as usize]
            ),
        }
    }

    // Construct results from return data
    construct_ret(hdr, payload, Ok((0, 0)));
    Ok(())
}
