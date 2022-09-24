// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::{debug, warn};
use rpc::rpc::RPCType;
use rpc::RPCClient;
use smoltcp::socket::UdpSocket;
use smoltcp::time::Instant;

use crate::transport::ethernet::ETHERNET_IFACE;

use super::super::kernelrpc::*;
use super::{DCMOps, DCM_INTERFACE};

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocRequest {
    pub application: u64,
    pub cores: u64,
    pub memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<AllocRequest>();

impl AllocRequest {
    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocRequest) as *mut u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocRequest) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocResponse {
    pub alloc_id: u64,
}
pub const RES_SIZE: usize = core::mem::size_of::<AllocResponse>();

impl AllocResponse {
    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocResponse) as *mut u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocResponse) as *const u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocAssignment {
    pub alloc_id: u64,
    pub node: u64,
}
pub const ALLOC_LEN: usize = core::mem::size_of::<AllocAssignment>();

impl AllocAssignment {
    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const AllocAssignment) as *mut u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_bytes(&self) -> &[u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts((self as *const AllocAssignment) as *const u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}

pub(crate) fn make_dcm_request(local_pid: usize, is_core: bool) -> u64 {
    let req = AllocRequest {
        application: 1,
        cores: if is_core { 1 } else { 0 },
        memslices: if is_core { 0 } else { 1 },
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
            .call(
                local_pid,
                DCMOps::ResourceRequest as RPCType,
                unsafe { &[req.as_bytes()] },
                unsafe { &mut [res.as_mut_bytes()] },
            )
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
    return assignment.node;
}
