// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use core::fmt::Debug;

use abomonation::decode;
use log::debug;
use rpc::rpc::*;
use rpc::RPCClient;

use crate::error::KError;
use crate::fs::cnrfs;
use crate::nr;

use super::super::kernelrpc::*;

// This isn't truly a syscall, but we'll reuse some infrastructure/types.
pub(crate) fn rpc_make_process(rpc_client: &mut dyn RPCClient) -> Result<usize, KError> {
    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<KernelRpcRes>()];
    rpc_client
        .call(
            0,
            KernelRpc::MakeProcess as RPCType,
            &[],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<KernelRpcRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData.into());
        }
        debug!("MakeProcess() {:?}", res);
        match res.ret {
            Ok((pid, _)) => Ok(pid as usize),
            Err(e) => Err(e.into()),
        }
    } else {
        Err(RPCError::MalformedResponse.into())
    }
}

// RPC Handler function for make_process() RPCs in the controller
pub(crate) fn handle_make_process(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
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
    let res = KernelRpcRes {
        ret: convert_return(ret),
    };
    construct_ret(hdr, payload, res)
}
