// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abomonation::{decode, Abomonation};
use alloc::string::String;
use alloc::vec::Vec;
use log::{debug, warn};

use kpi::io::{FileFlags, FileModes};
use rpc::rpc::*;

use crate::arch::exokernel::syscalls::*;
use crate::cnrfs;

#[derive(Debug)]
pub struct OpenReq {
    pub pathname: String,
    pub flags: u64,
    pub modes: u64,
}
unsafe_abomonate!(OpenReq: pathname, flags, modes);

pub fn handle_open(hdr: &mut Vec<u8>, payload: &mut Vec<u8>) -> Result<(), RPCError> {
    let local_pid = {
        // Parse header
        let (parsed_hdr, _) = unsafe { decode::<RPCHeader>(hdr) }.unwrap();

        // Lookup local pid
        get_local_pid(parsed_hdr.pid)
    };

    if local_pid.is_none() {
        return construct_error_ret(hdr, payload, RPCError::NoFileDescForPid);
    }
    let local_pid = local_pid.unwrap();

    // Parse body
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
            return construct_error_ret(hdr, payload, RPCError::ExtraData);
        }

        // TODO: FIX DATA COPY
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
        construct_ret(hdr, payload, res)
    } else {
        warn!("Invalid payload for request: {:?}", hdr);
        construct_error_ret(hdr, payload, RPCError::MalformedRequest)
    }
}
