// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{encode, Abomonation};
use alloc::vec::Vec;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error};

use rpc::cluster_api::NodeId;
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
pub fn construct_ret(
    hdr: &mut RPCHeader,
    payload: &mut [u8],
    res: FIORes,
) -> Result<(), RPCError> {
    // Encode payload in buffer
    // TODO: don't want to need to call to_vec()
    unsafe { encode(&res, &mut payload.to_vec()) }.unwrap();

    // Modify header and write into output buffer
    hdr.msg_len = core::mem::size_of::<FIORes>() as u64;
    Ok(())
}

#[inline(always)]
pub fn convert_return(cnrfs_ret: Result<(u64, u64), KError>) -> Result<(u64, u64), RPCError> {
    match cnrfs_ret {
        Ok(ret) => Ok(ret),
        Err(err) => Err(err.into()),
    }
}

/*
/// RPC handler for file operations
pub fn handle_fileio(hdr: &RPCHeader, payload: &mut [u8]) -> Vec<u8> {
    let mut res_hdr = RPCHeader {
        client_id: hdr.client_id,
        pid: hdr.pid,
        req_id: hdr.req_id,
        msg_type: hdr.msg_type,
        msg_len: 0,
    };

    let process_lookup = PID_MAP.read();
    let local_pid = process_lookup.get(&hdr.pid);
    if let None = local_pid {
        error!("Failed to lookup remote pid {}", hdr.pid);
        return construct_error_ret(res_hdr, RPCError::NoFileDescForPid);
    }
    let local_pid = *(local_pid.unwrap());

    match FileIO::from(hdr.msg_type) {
        FileIO::Create => {
            unreachable!("Create is changed to Open with O_CREAT flag in vibrio")
        }
        FileIO::Open => {
            if let Some((req, remaining)) = unsafe { decode::<OpenReq>(payload) } {
                debug!(
                    "Open(pathname={:?}, flags={:?}, modes={:?}), local_pid={:?}",
                    req.pathname,
                    FileFlags::from(req.flags),
                    FileModes::from(req.modes),
                    local_pid
                );
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let mut pathname = req.pathname.clone();
                pathname.push('\0');

                let res = FIORes {
                    ret: convert_return(cnrfs::MlnrKernelNode::map_fd(
                        local_pid,
                        pathname.as_ptr() as u64,
                        req.flags,
                        req.modes,
                    )),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::Read | FileIO::ReadAt => {
            if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
                debug!(
                    "Read(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
                    req.fd, req.len, req.offset, local_pid
                );
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                // TODO: allocate buffer, extract bytes read
                let mut buf = [0; MAX_READ];
                let ret = if hdr.msg_type == FileIO::Read as RPCType {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::Read,
                        local_pid,
                        req.fd,
                        buf.as_mut_ptr() as u64,
                        req.len,
                        -1,
                    )
                } else {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::ReadAt,
                        local_pid,
                        req.fd,
                        buf.as_mut_ptr() as u64,
                        req.len,
                        req.offset,
                    )
                };

                let mut res_data = Vec::new();
                let res = FIORes {
                    ret: convert_return(ret),
                };

                match res.ret {
                    Ok((bytes_read, _)) => {
                        unsafe { encode(&res, &mut res_data) }.unwrap();
                        res_data.extend(&buf[0..(bytes_read as usize)]);
                    }
                    _ => unsafe { encode(&res, &mut res_data) }.unwrap(),
                };
                res_hdr.msg_len = res_data.len() as u64;

                let mut data = Vec::new();
                unsafe { encode(&res_hdr, &mut data) }.unwrap();
                data.extend(res_data);
                data
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::Write | FileIO::WriteAt => {
            if let Some((req, remaining)) = unsafe { decode::<RWReq>(payload) } {
                debug!(
                    "Write(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
                    req.fd, req.len, req.offset, local_pid
                );
                if remaining.len() as u64 != req.len {
                    return construct_error_ret(res_hdr, RPCError::MalformedRequest);
                }

                let ret = if hdr.msg_type == FileIO::Write as RPCType {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::Write,
                        local_pid,
                        req.fd,
                        remaining.as_mut_ptr() as u64,
                        req.len,
                        -1,
                    )
                } else {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::WriteAt,
                        local_pid,
                        req.fd,
                        remaining.as_mut_ptr() as u64,
                        req.len,
                        req.offset,
                    )
                };

                let res = FIORes {
                    ret: convert_return(ret),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::Close => {
            if let Some((req, remaining)) = unsafe { decode::<CloseReq>(payload) } {
                debug!("Close(fd={:?}), local_pid={:?}", req.fd, local_pid);
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                let res = FIORes {
                    ret: convert_return(cnrfs::MlnrKernelNode::unmap_fd(local_pid, req.fd)),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::GetInfo => {
            if let Some((req, remaining)) = unsafe { decode::<GetInfoReq>(payload) } {
                debug!("GetInfo(name={:?}), local_pid={:?}", req.name, local_pid);
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let fileinfo: FileInfo = Default::default();
                let mut name = req.name.clone();
                name.push('\0');

                let mut ret = cnrfs::MlnrKernelNode::file_info(
                    local_pid,
                    name.as_ptr() as u64,
                    &fileinfo as *const FileInfo as u64,
                );
                if ret.is_ok() {
                    ret = Ok((fileinfo.ftype, fileinfo.fsize));
                }
                debug!("GetInfo() returned ret={:?} fileinfo={:?}", ret, fileinfo);
                let res = FIORes {
                    ret: convert_return(ret),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::Delete => {
            if let Some((req, remaining)) = unsafe { decode::<DeleteReq>(payload) } {
                debug!("Delete(name={:?}), local_pid={:?}", req.pathname, local_pid);
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let mut pathname = req.pathname.clone();
                pathname.push('\0');
                let res = FIORes {
                    ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
                        local_pid,
                        pathname.as_ptr() as u64,
                    )),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::FileRename => {
            if let Some((req, remaining)) = unsafe { decode::<RenameReq>(payload) } {
                debug!(
                    "FileRename(oldname={:?}, newname={:?}), local_pid={:?}",
                    req.oldname, req.newname, local_pid
                );
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::MalformedRequest);
                }
                let mut oldname = req.oldname.clone();
                oldname.push('\0');
                let mut newname = req.newname.clone();
                newname.push('\0');
                let res = FIORes {
                    ret: convert_return(cnrfs::MlnrKernelNode::file_rename(
                        local_pid,
                        oldname.as_ptr() as u64,
                        newname.as_ptr() as u64,
                    )),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        FileIO::MkDir => {
            if let Some((req, remaining)) = unsafe { decode::<OpenReq>(payload) } {
                debug!(
                    "MkDir(pathname={:?}), local_pid={:?}",
                    req.pathname, local_pid
                );
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let res = FIORes {
                    ret: convert_return(cnrfs::MlnrKernelNode::mkdir(
                        local_pid,
                        req.pathname.as_ptr() as u64,
                        req.modes,
                    )),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        _ => construct_error_ret(res_hdr, RPCError::NotSupported),
    }
}
*/
