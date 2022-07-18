// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryFrom;

use abomonation::{encode, unsafe_abomonate, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error};

use rpc::rpc::*;

use crate::error::KError;
use crate::fs::{cnrfs, NrLock};
use crate::nr;
use crate::process::Pid;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub(crate) enum KernelRpc {
    /// Create a file
    Create = 0,
    /// Open a file
    Open = 1,
    /// Read from a file
    Read = 2,
    /// Read from a file from the given offset
    ReadAt = 3,
    /// Write to a file
    Write = 4,
    /// Write to a file
    WriteAt = 5,
    /// Close an opened file.
    Close = 6,
    /// Get the information related to the file.
    GetInfo = 7,
    /// Delete the file
    Delete = 8,
    /// Write to a file without going into NR.
    WriteDirect = 9,
    /// Rename a file.
    FileRename = 10,
    /// Create a directory.
    MkDir = 11,
    /// Log (print) message of a process.
    Log = 12,
    /// Allocate physical memory for a process.
    AllocPhysical = 13,
}

impl TryFrom<RPCType> for KernelRpc {
    type Error = KError;

    /// Construct a RPCType enum based on a 8-bit value.
    fn try_from(op: RPCType) -> Result<Self, Self::Error> {
        match op {
            0 => Ok(KernelRpc::Create),
            1 => Ok(KernelRpc::Open),
            2 => Ok(KernelRpc::Read),
            3 => Ok(KernelRpc::ReadAt),
            4 => Ok(KernelRpc::Write),
            5 => Ok(KernelRpc::WriteAt),
            6 => Ok(KernelRpc::Close),
            7 => Ok(KernelRpc::GetInfo),
            8 => Ok(KernelRpc::Delete),
            9 => Ok(KernelRpc::WriteDirect),
            10 => Ok(KernelRpc::FileRename),
            11 => Ok(KernelRpc::MkDir),
            12 => Ok(KernelRpc::Log),
            13 => Ok(KernelRpc::AllocPhysical),
            _ => Err(KError::InvalidRpcType),
        }
    }
}
unsafe_abomonate!(KernelRpc);

// Struct used to encapulate a system call result
#[derive(Debug)]
pub(crate) struct KernelRpcRes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(KernelRpcRes: ret);
pub(crate) const KernelRpcRes_SIZE: u64 = core::mem::size_of::<KernelRpcRes>() as u64;

// Mapping between local PIDs and remote (client) PIDs
lazy_static! {
    static ref PID_MAP: NrLock<HashMap<Pid, Pid>> = NrLock::default();
}

// Lookup the local pid corresponding to a remote pid
pub(crate) fn get_local_pid(remote_pid: Pid) -> Option<Pid> {
    let process_lookup = PID_MAP.read();
    let local_pid = process_lookup.get(&remote_pid);
    if let None = local_pid {
        error!("Failed to lookup remote pid {}", remote_pid);
        return None;
    }
    Some(*(local_pid.unwrap()))
}

// Register a remote pid by creating a local pid and creating a remote-local PID mapping
pub(crate) fn register_pid(remote_pid: usize) -> Result<usize, KError> {
    crate::nr::NR_REPLICA
        .get()
        .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
            let response = replica.execute_mut(nr::Op::AllocatePid, *token)?;
            if let nr::NodeResult::PidAllocated(local_pid) = response {
                // TODO: some way to unwind if fails??
                match cnrfs::MlnrKernelNode::add_process(local_pid) {
                    Ok(_) => {
                        // TODO: register pid
                        let mut pmap = PID_MAP.write();
                        pmap.try_reserve(1)?;
                        pmap.try_insert(remote_pid, local_pid)
                            .map_err(|_e| KError::FileDescForPidAlreadyAdded)?;
                        debug!(
                            "Mapped remote pid {} to local pid {}",
                            remote_pid, local_pid
                        );
                        Ok(local_pid)
                    }
                    Err(err) => {
                        error!("Unable to register pid {:?} {:?}", remote_pid, err);
                        Err(KError::NoProcessFoundForPid)
                    }
                }
            } else {
                Err(KError::NoProcessFoundForPid)
            }
        })
}

// RPC Handler for client registration
pub(crate) fn register_client(
    hdr: &mut RPCHeader,
    _payload: &mut [u8],
) -> Result<NodeId, RPCError> {
    // use local pid as client ID
    match register_pid(hdr.pid) {
        Ok(client_id) => Ok(client_id as NodeId),
        Err(err) => Err(err.into()),
    }
}

// Below are utility functions for working with KernelRpcRes

#[inline(always)]
pub(crate) fn construct_error_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    err: RPCError,
) -> Result<(), RPCError> {
    let res = KernelRpcRes { ret: Err(err) };
    construct_ret(hdr, payload, res)
}

#[inline(always)]
pub(crate) fn construct_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    res: KernelRpcRes,
) -> Result<(), RPCError> {
    construct_ret_extra_data(hdr, payload, res, 0)
}

#[inline(always)]
pub(crate) fn construct_ret_extra_data(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    res: KernelRpcRes,
    additional_data_len: u64,
) -> Result<(), RPCError> {
    // Encode payload in buffer
    unsafe { encode(&res, &mut payload) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = KernelRpcRes_SIZE + additional_data_len;
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
