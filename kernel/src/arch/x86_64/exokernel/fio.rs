// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{encode, Abomonation};
use core2::io::Result as IOResult;
use core2::io::Write;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error};

use rpc::rpc::*;

use crate::error::KError;
use crate::fs::NrLock;
use crate::process::Pid;
use crate::{cnrfs, nr};

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Copy)]
#[repr(u8)]
pub enum FileIO {
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

    Unknown = 12,
}

impl From<RPCType> for FileIO {
    /// Construct a RPCType enum based on a 8-bit value.
    fn from(op: RPCType) -> FileIO {
        match op {
            0 => FileIO::Create,
            1 => FileIO::Open,
            2 => FileIO::Read,
            3 => FileIO::ReadAt,
            4 => FileIO::Write,
            5 => FileIO::WriteAt,
            6 => FileIO::Close,
            7 => FileIO::GetInfo,
            8 => FileIO::Delete,
            9 => FileIO::WriteDirect,
            10 => FileIO::FileRename,
            11 => FileIO::MkDir,
            _ => FileIO::Unknown,
        }
    }
}
unsafe_abomonate!(FileIO);

#[derive(Debug)]
pub struct FIORes {
    pub ret: Result<(u64, u64), RPCError>,
}
unsafe_abomonate!(FIORes: ret);
pub const FIORES_SIZE: u64 = core::mem::size_of::<FIORes>() as u64;

lazy_static! {
    static ref PID_MAP: NrLock<HashMap<Pid, Pid>> = NrLock::default();
}

pub fn get_local_pid(remote_pid: usize) -> Option<usize> {
    let process_lookup = PID_MAP.read();
    let local_pid = process_lookup.get(&remote_pid);
    if let None = local_pid {
        error!("Failed to lookup remote pid {}", remote_pid);
        return None;
    }
    Some(*(local_pid.unwrap()))
}

pub fn register_pid(remote_pid: usize) -> Result<usize, KError> {
    let kcb = super::super::kcb::get_kcb();
    kcb.replica
        .as_ref()
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

pub fn register_client(hdr: &mut RPCHeader, _payload: &mut [u8]) -> Result<NodeId, RPCError> {
    // use local pid as client ID
    match register_pid(hdr.pid) {
        Ok(client_id) => Ok(client_id as NodeId),
        Err(err) => Err(err.into()),
    }
}

#[inline(always)]
pub fn construct_error_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    err: RPCError,
) -> Result<(), RPCError> {
    let res = FIORes { ret: Err(err) };
    construct_ret(hdr, payload, res)
}

#[inline(always)]
pub fn construct_ret(hdr: &mut RPCHeader, payload: &mut [u8], res: FIORes) -> Result<(), RPCError> {
    construct_ret_extra_data(hdr, payload, res, 0)
}

#[inline(always)]
pub fn construct_ret_extra_data(
    hdr: &mut RPCHeader,
    mut payload: &mut [u8],
    res: FIORes,
    additional_data_len: u64,
) -> Result<(), RPCError> {
    // Encode payload in buffer
    unsafe { encode(&res, &mut payload) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = FIORES_SIZE + additional_data_len;
    Ok(())
}

#[inline(always)]
pub fn convert_return(cnrfs_ret: Result<(u64, u64), KError>) -> Result<(u64, u64), RPCError> {
    match cnrfs_ret {
        Ok(ret) => Ok(ret),
        Err(err) => Err(err.into()),
    }
}
