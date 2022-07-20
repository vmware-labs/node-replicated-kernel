// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use log::{debug, warn};
use rpc::rpc::*;
use rpc::RPCClient;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use crate::transport::ethernet::ETHERNET_IFACE;

use super::super::syscall_res::*;
use super::dcm_msg::{AllocAssignment, AllocRequest, AllocResponse};
use super::get_local_pid;
use super::ResourceRequest;
use super::DCM_INTERFACE;

#[derive(Debug)]
pub(crate) struct AllocatePhysicalRequest {
    pub page_size: u64,
    pub affinity: u64,
}
unsafe_abomonate!(AllocatePhysicalRequest: page_size, affinity);

pub(crate) fn rpc_allocate_physical(
    rpc_client: &mut dyn RPCClient,
    pid: usize,
    page_size: u64,
    affinity: u64,
) -> Result<(u64, u64), RPCError> {
    debug!("AllocatePhysical({:?}, {:?})", page_size, affinity);

    // Construct request data
    let req = AllocatePhysicalRequest {
        page_size,
        affinity,
    };
    let mut req_data = [0u8; core::mem::size_of::<AllocatePhysicalRequest>()];
    unsafe { encode(&req, &mut (&mut req_data).as_mut()) }.unwrap();

    // Construct result buffer and call RPC
    let mut res_data = [0u8; core::mem::size_of::<SyscallRes>()];
    rpc_client
        .call(
            pid,
            ResourceRequest::Memory as RPCType,
            &[&req_data],
            &mut [&mut res_data],
        )
        .unwrap();

    // Decode and return the result
    if let Some((res, remaining)) = unsafe { decode::<SyscallRes>(&mut res_data) } {
        if remaining.len() > 0 {
            return Err(RPCError::ExtraData);
        }
        debug!("AllocatePhysical() {:?}", res);
        return res.ret;
    } else {
        return Err(RPCError::MalformedResponse);
    }
}

// RPC Handler function for delete() RPCs in the controller
pub(crate) fn handle_allocate_physical(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
) -> Result<(), RPCError> {
    // Lookup local pid
    let local_pid = { get_local_pid(hdr.pid) };
    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse request
    let mem_req = match unsafe { decode::<AllocatePhysicalRequest>(payload) } {
        Some((req, _)) => req,
        None => {
            warn!("Invalid payload for request: {:?}", hdr);
            return construct_error_ret(hdr, payload, RPCError::MalformedRequest);
        }
    };

    let req = AllocRequest {
        application: 1, // TODO: what is application, in this context?
        cores: 0,
        memslices: 1, // TODO: map page_size to number of memslices
    };
    let mut res = AllocResponse { alloc_id: 0 };
    let mut assignment = AllocAssignment {
        alloc_id: 0,
        node: 0,
    };

    // Send call, get allocation response in return
    {
        DCM_INTERFACE
            .lock()
            .client
            .call(local_pid, 1, unsafe { &[req.as_bytes()] }, unsafe {
                &mut [res.as_mut_bytes()]
            })
            .unwrap();
        debug!("Received allocation id in response: {:?}", res.alloc_id);
    }

    let mut received_allocation = false;
    while !received_allocation {
        {
            let mut my_iface = ETHERNET_IFACE.lock();
            let socket = my_iface.get_socket::<UdpSocket>(DCM_INTERFACE.lock().udp_handle);
            if socket.can_recv() {
                match socket.recv_slice(unsafe { assignment.as_mut_bytes() }) {
                    Ok((_, endpoint)) => {
                        debug!(
                            "Received assignment: {:?} to node {:?}",
                            assignment.alloc_id, assignment.node
                        );
                        if assignment.alloc_id != res.alloc_id {
                            warn!("AllocIds do not match!");
                        }
                        socket.send_slice(&[1u8], endpoint).unwrap();
                        received_allocation = true;
                    }
                    Err(e) => {
                        debug!("Received nothing? {:?}", e);
                    }
                }
            }
        }

        match ETHERNET_IFACE.lock().poll(Instant::from_millis(
            rawtime::duration_since_boot().as_millis() as i64,
        )) {
            Ok(_) => {}
            Err(e) => {
                warn!("poll error: {}", e);
            }
        }
    }

    debug!("Ready to send response!");

    // Construct and return result
    let res = SyscallRes {
        ret: convert_return(Ok((assignment.node, 0))),
    };
    construct_ret(hdr, payload, res)
}
