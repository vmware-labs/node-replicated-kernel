//! System calls to query for generic system-wide information.
//! (topology, memory, device hardware etc.)

use alloc::vec::Vec;

use crate::syscall;
use crate::*;

use crate::system::CpuThread;

pub struct System;

impl System {
    /// Query information about available hardware threads.
    pub fn threads() -> Result<Vec<CpuThread>, SystemCallError> {
        let mut buf = alloc::vec![0; 8192];
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
            let deserialized: Vec<CpuThread> = serde_cbor::from_slice(&buf).unwrap();
            Ok(deserialized)
        } else {
            Err(SystemCallError::from(r))
        }
    }
}
