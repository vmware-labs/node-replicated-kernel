// Copyright © 2022 University of Colorado and VMware Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;

use kpi::system::{mid_from_gtid, ThreadId};
use rpc::rpc::*;

use super::super::dcm::resource_release::dcm_resource_release;
use super::super::kernelrpc::*;
use super::super::CLIENT_STATE;
use crate::error::{KError, KResult};
use crate::nr::KernelNode;
use crate::process::Pid;

#[derive(Debug)]
pub(crate) struct ReleaseCoreReq {
    pub pid: Pid,
    pub gtid: ThreadId,
}
unsafe_abomonate!(ReleaseCoreReq: pid, gtid);

/// RPC to forward physical memory release to controller.
pub(crate) fn rpc_release_core(pid: Pid, gtid: ThreadId) -> KResult<(u64, u64)> {
    log::debug!("ReleaseCore({:?})", gtid);

    // TODO(rackscale, error_handling): will probably want to do this NrProcess operation on controller,
    // so we can't have a state where this succeeds but the next part fails without the controller knowing.
    let gtid_affinity = mid_from_gtid(gtid);
    KernelNode::release_core_from_process(pid, Some(gtid_affinity), gtid)?;

    let req = ReleaseCoreReq { pid, gtid };
    let mut req_data = [0u8; core::mem::size_of::<ReleaseCoreReq>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }
        .expect("Failed to encode release core request");

    // Create result buffer
    let mut res_data = [0u8; core::mem::size_of::<KResult<(u64, u64)>>()];
    CLIENT_STATE.rpc_client.lock().call(
        KernelRpc::ReleaseCore as RPCType,
        &[&req_data],
        &mut [&mut res_data],
    )?;

    // Decode result, return result if decoded successfully
    if let Some((res, remaining)) = unsafe { decode::<KResult<(u64, u64)>>(&mut res_data) } {
        if remaining.len() > 0 {
            log::error!("Release core RPC failed with extra data");
            Err(KError::from(RPCError::ExtraData))
        } else {
            log::debug!("ReleaseCore({:?}) = {:?}", gtid, *res);
            *res
        }
    } else {
        Err(KError::from(RPCError::MalformedResponse))
    }
}

/// RPC handler for releasing physical memory on the controller.
pub(crate) fn handle_release_core(hdr: &mut RPCHeader, payload: &mut [u8]) -> Result<(), RPCError> {
    // Extract data needed from the request
    let req = match unsafe { decode::<ReleaseCoreReq>(payload) } {
        Some((req, _)) => req,
        _ => {
            log::error!("Invalid payload for request: {:?}", hdr);
            construct_error_ret(hdr, payload, KError::from(RPCError::MalformedRequest));
            return Ok(());
        }
    };
    let mid = mid_from_gtid(req.gtid);
    log::debug!(
        "ReleaseCore(pid={:x?}, gtid={:?}) mid={:?}",
        req.pid,
        req.gtid,
        mid,
    );

    // Construct result. For success, both DCM and the manager need to release the memory
    let res = {
        // Tell DCM the resource is no longer being used
        if dcm_resource_release(mid, req.pid, true) == 0 {
            log::debug!("DCM release resource was successful");
            Ok((0, 0))
        } else {
            log::error!("DCM release resource failed");
            // TODO: not sure if this is the best error to send
            Err(KError::DCMError)
        }
    };
    construct_ret(hdr, payload, res);
    Ok(())
}
