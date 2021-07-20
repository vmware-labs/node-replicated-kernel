use abomonation::{decode, encode};
use alloc::vec::Vec;
use log::warn;

use kpi::io::FileInfo;
use kpi::FileOperation;
use rpc::rpc::*;

use crate::cnrfs;
use crate::error::KError;

const MAX_READ: usize = 4096;

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

/// RPC handler for file operations
pub fn handle_fileio(hdr: &RPCHeader, payload: &mut [u8]) -> Vec<u8> {
    let mut res_hdr = RPCHeader {
        client_id: hdr.client_id,
        pid: hdr.pid,
        req_id: hdr.req_id,
        msg_type: hdr.msg_type,
        msg_len: 0,
    };
    match hdr.msg_type {
        RPCType::Create => {
            unreachable!("Create is changed to Open with O_CREAT flag in vibrio")
        }
        RPCType::Open => {
            if let Some((req, remaining)) = unsafe { decode::<RPCOpenReq>(payload) } {
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::map_fd(
                        hdr.pid,
                        req.pathname.as_ptr() as u64,
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
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                // TODO: allocate buffer, extract bytes read
                let mut buf = [0; MAX_READ];
                let ret = if hdr.msg_type == RPCType::Read {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::Read,
                        hdr.pid,
                        req.fd,
                        buf.as_mut_ptr() as u64,
                        req.len,
                        -1,
                    )
                } else {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::ReadAt,
                        hdr.pid,
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
                if remaining.len() as u64 != req.len {
                    return construct_error_ret(res_hdr, RPCError::MalformedRequest);
                }

                let ret = if hdr.msg_type == RPCType::Write {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::Write,
                        hdr.pid,
                        req.fd,
                        remaining.as_mut_ptr() as u64,
                        req.len,
                        -1,
                    )
                } else {
                    cnrfs::MlnrKernelNode::file_io(
                        FileOperation::WriteAt,
                        hdr.pid,
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
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::unmap_fd(hdr.pid, req.fd)),
                };
                construct_ret(res_hdr, res)
            } else {
                warn!("Invalid payload for request: {:?}", hdr);
                construct_error_ret(res_hdr, RPCError::MalformedRequest)
            }
        }
        RPCType::GetInfo => {
            if let Some((req, remaining)) = unsafe { decode::<RPCGetInfoReq>(payload) } {
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }

                let file_info = [0u8; core::mem::size_of::<FileInfo>()];
                let ret = cnrfs::MlnrKernelNode::file_info(
                    hdr.pid,
                    req.name.as_ptr() as u64,
                    file_info.as_ptr() as u64,
                );
                let res = FIORPCRes {
                    ret: convert_return(ret),
                };

                // cannot use function because of extra data
                let mut res_data = Vec::new();
                unsafe { encode(&res, &mut res_data) }.unwrap();
                res_data.extend(file_info);
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
        RPCType::Delete => {
            if let Some((req, remaining)) = unsafe { decode::<RPCDeleteReq>(payload) } {
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::file_delete(
                        hdr.pid,
                        req.pathname.as_ptr() as u64,
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
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::MalformedRequest);
                }
                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::file_rename(
                        hdr.pid,
                        req.oldname.as_ptr() as u64,
                        req.newname.as_ptr() as u64,
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
                if remaining.len() > 0 {
                    warn!("Trailing data in payload: {:?}", remaining);
                    return construct_error_ret(res_hdr, RPCError::ExtraData);
                }
                let res = FIORPCRes {
                    ret: convert_return(cnrfs::MlnrKernelNode::mkdir(
                        hdr.pid,
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
