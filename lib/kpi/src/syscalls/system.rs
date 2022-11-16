// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! System calls to query for generic system-wide information.
//! (topology, memory, device hardware etc.)

use alloc::vec::Vec;

use abomonation::decode;

use crate::{syscall, *};

use crate::system::{CoreId, CpuThread};

pub struct System;

impl System {
    /// Query information about available hardware threads.
    pub fn threads() -> Result<Vec<CpuThread>, SystemCallError> {
        let mut buf = alloc::vec![0; 5*4096];
        let (r, len) = unsafe {
            syscall!(
                SystemCall::System as u64,
                SystemOperation::GetHardwareThreads as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                2
            )
        };

        if r == 0 {
            let len = len as usize;
            debug_assert!(len <= buf.len());
            buf.resize(len, 0);
            if let Some((deserialized, remaining)) =
                unsafe { decode::<Vec<CpuThread>>(&mut buf[..len]) }
            {
                if remaining.len() > 0 {
                    Err(SystemCallError::InternalError)
                } else {
                    // This does perform a copy, which is less than ideal.
                    Ok(deserialized.to_vec())
                }
            } else {
                Err(SystemCallError::InternalError)
            }
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Prints some stats for the core.
    pub fn stats() -> Result<(), SystemCallError> {
        let r = unsafe { syscall!(SystemCall::System as u64, SystemOperation::Stats as u64, 1) };

        if r == 0 {
            Ok(())
        } else {
            Err(SystemCallError::from(r))
        }
    }

    /// Get the core id for the current running thread.
    pub fn core_id() -> Result<CoreId, SystemCallError> {
        let (r, id) = unsafe {
            syscall!(
                SystemCall::System as u64,
                SystemOperation::GetCoreID as u64,
                2
            )
        };

        if r == 0 {
            Ok(id as usize)
        } else {
            Err(SystemCallError::from(r))
        }
    }
}
