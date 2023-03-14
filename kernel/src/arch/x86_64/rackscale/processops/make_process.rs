// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::{KError, KResult};
use crate::fs::cnrfs;
use crate::nr;

use super::super::controller_state::ControllerState;
use super::super::kernelrpc::*;

// This isn't truly a syscall, but we'll reuse some infrastructure/types.
pub(crate) fn rpc_make_process(rpc_client: &mut dyn RPCClient) -> Result<usize, KError> {
    debug!("MakeProcess()");

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    rpc_client.call(KernelRpc::MakeProcess as RPCType, &[], &mut [&mut res_data])?;

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(KError::from(RPCError::ExtraData));
        }
        debug!("MakeProcess() {:?}", res);
        match res {
            Ok((pid, _)) => Ok(*pid as usize),
            Err(e) => Err(*e),
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

// RPC Handler function for make_process() RPCs in the controller
pub(crate) fn handle_make_process(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    state: ControllerState,
) -> Result<ControllerState, RPCError> {
    // Create a new process and return the pid
    let ret = nr::NR_REPLICA
        .get()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::AllocatePid, *token)?;
            if let nr::NodeResult::PidAllocated(pid) = response {
                cnrfs::MlnrKernelNode::add_process(pid)
                    .expect("TODO(error-handling): revert state");
                log::info!("Created process {:?} on controller", pid);
                Ok(pid)
            } else {
                Err(KError::ProcessLoadingFailed)
            }
        })
        .map(|pid| (pid as u64, 0));

    // Construct results from return data
    construct_ret(hdr, payload, ret);
    Ok(state)
}
