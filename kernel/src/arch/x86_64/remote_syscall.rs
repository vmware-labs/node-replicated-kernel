use abomonation::{decode, encode};
use alloc::vec::Vec;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::{debug, error, warn};

use kpi::io::{FileFlags, FileInfo, FileModes};
use kpi::FileOperation;
use rpc::rpc::*;

use crate::error::KError;
use crate::fs::NrLock;
use crate::process::Pid;
use crate::{cnrfs, nr};

const MAX_READ: usize = 4096;

lazy_static! {
    static ref PID_MAP: NrLock<HashMap<Pid, Pid>> = NrLock::default();
}

#[inline(always)]
fn construct_error_ret(res_hdr: RPCHeader, err: RPCError) -> Vec<u8> {
    let res = FIORPCRes { ret: Err(err) };
    construct_ret(res_hdr, res)
}

#[inline(always)]
fn construct_ret(mut res_hdr: RPCHeader, res: FIORPCRes) -> Vec<u8> {
    let mut res_data = Vec::new();
    unsafe { encode(&res, &mut res_data) }.unwrap();
    res_hdr.msg_len = res_data.len() as u64;

    let mut data = Vec::new();
    unsafe { encode(&res_hdr, &mut data) }.unwrap();
    data.extend(res_data);
    data
}

#[inline(always)]
fn convert_return(cnrfs_ret: Result<(u64, u64), KError>) -> Result<(u64, u64), RPCError> {
    match cnrfs_ret {
        Ok(ret) => Ok(ret),
        Err(err) => Err(err.into()),
    }
}

pub fn register_pid(remote_pid: usize) -> Result<(), KError> {
    let kcb = super::kcb::get_kcb();
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
                        Ok(())
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

    match hdr.msg_type {
        RPCType::Create => {
            unreachable!("Create is changed to Open with O_CREAT flag in vibrio")
        }
        RPCType::Open => {
            if let Some((req, remaining)) = unsafe { decode::<RPCOpenReq>(payload) } {
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

                let res = FIORPCRes {
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
        RPCType::Read | RPCType::ReadAt => {
            if let Some((req, remaining)) = unsafe { decode::<RPCRWReq>(payload) } {
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
                let ret = if hdr.msg_type == RPCType::Read {
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
                let res = FIORPCRes {
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
        RPCType::Write | RPCType::WriteAt => {
            if let Some((req, remaining)) = unsafe { decode::<RPCRWReq>(payload) } {
                debug!(
                    "Write(At)(fd={:?}, len={:?}, offset={:?}), local_pid={:?}",
                    req.fd, req.len, req.offset, local_pid
                );
                if remaining.len() as u64 != req.len {
                    return construct_error_ret(res_hdr, RPCError::MalformedRequest);
                }

                let ret = if hdr.msg_type == RPCType::Write {
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

                let res = FIORPCRes {
                    ret: convert_return(ret),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        RPCType::Close => {
            if let Some((req, remaining)) = unsafe { decode::<RPCCloseReq>(payload) } {
                debug!("Close(fd={:?}), local_pid={:?}", req.fd, local_pid);
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::unmap_fd(local_pid, req.fd)),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        RPCType::GetInfo => {
            if let Some((req, remaining)) = unsafe { decode::<RPCGetInfoReq>(payload) } {
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
                let res = FIORPCRes {
                    ret: convert_return(ret),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        RPCType::Delete => {
            if let Some((req, remaining)) = unsafe { decode::<RPCDeleteReq>(payload) } {
                debug!("Delete(name={:?}), local_pid={:?}", req.pathname, local_pid);
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let mut pathname = req.pathname.clone();
                pathname.push('\0');
                let res = FIORPCRes {
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
        RPCType::FileRename => {
            if let Some((req, remaining)) = unsafe { decode::<RPCRenameReq>(payload) } {
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
                let res = FIORPCRes {
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
        RPCType::MkDir => {
            if let Some((req, remaining)) = unsafe { decode::<RPCOpenReq>(payload) } {
                debug!(
                    "MkDir(pathname={:?}), local_pid={:?}",
                    req.pathname, local_pid
                );
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let res = FIORPCRes {
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
