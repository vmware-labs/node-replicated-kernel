#![allow(unused)]

use crate::error::KError;
use crate::mlnrfs::{Buffer, Filename, Flags, Len, MlnrFS, Modes, Offset, FD};
use crate::prelude::*;
use crate::process::{userptr_to_str, Eid, Executor, KernSlice, Pid, Process, ProcessError};

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use kpi::{io::*, FileOperation};
use mlnr::{Dispatch, LogMapper, ReplicaToken};

pub struct MlnrKernelNode {
    counters: Vec<CachePadded<AtomicUsize>>,
    fs: MlnrFS,
}

impl Default for MlnrKernelNode {
    fn default() -> Self {
        let max_cores = 192;
        let mut counters = Vec::with_capacity(max_cores);
        for _i in 0..max_cores {
            counters.push(Default::default());
        }
        MlnrKernelNode {
            counters,
            fs: MlnrFS::default(),
        }
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Modify {
    Increment(usize),
    FileOpen(Pid, String, Flags, Modes),
    FileWrite(Pid, FD, Arc<[u8]>, Len, Offset),
    FileClose(Pid, FD),
    FileDelete(Pid, String),
    FileRename(Pid, String, String),
}

impl LogMapper for Modify {
    fn hash(&self) -> usize {
        0
    }
}

impl Default for Modify {
    fn default() -> Self {
        Modify::Increment(0)
    }
}

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Access {
    Get,
    FileRead(Pid, FD, Buffer, Len, Offset),
    FileInfo(Pid, Filename, u64),
}

impl LogMapper for Access {
    fn hash(&self) -> usize {
        0
    }
}

#[derive(Clone, Debug)]
pub enum MlnrNodeResult {
    Incremented(u64),
    FileAccessed(Len),
}

impl MlnrKernelNode {
    pub fn mlnr_direct_bench() -> Result<(u64, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| {
                let response = replica.execute_mut(Modify::Increment(token.id()), *token);
                match &response {
                    Ok(MlnrNodeResult::Incremented(val)) => Ok((*val, 0)),
                    Ok(_) => unreachable!("Got unexpected response"),
                    Err(e) => Err(e.clone()),
                }
            })
    }

    pub fn file_io(
        op: FileOperation,
        pid: Pid,
        fd: u64,
        buffer: u64,
        len: u64,
        offset: i64,
    ) -> Result<(Len, u64), KError> {
        let kcb = super::kcb::get_kcb();
        kcb.arch
            .mlnr_replica
            .as_ref()
            .map_or(Err(KError::ReplicaNotSet), |(replica, token)| match op {
                FileOperation::Write | FileOperation::WriteAt => {
                    let kernslice = KernSlice::new(buffer, len as usize);

                    let response = replica.execute_mut(
                        Modify::FileWrite(pid, fd, kernslice.buffer.clone(), len, offset),
                        *token,
                    );

                    match &response {
                        Ok(MlnrNodeResult::FileAccessed(len)) => Ok((*len, 0)),
                        Ok(_) => unreachable!("Got unexpected response"),
                        Err(r) => Err(r.clone()),
                    }
                }
                _ => unreachable!(),
            })
    }
}

impl Dispatch for MlnrKernelNode {
    type ReadOperation = Access;
    type WriteOperation = Modify;
    type Response = Result<MlnrNodeResult, KError>;

    fn dispatch(&self, _op: Self::ReadOperation) -> Self::Response {
        Ok(MlnrNodeResult::Incremented(
            self.counters[0].load(Ordering::Relaxed) as u64,
        ))
    }

    fn dispatch_mut(&self, op: Self::WriteOperation) -> Self::Response {
        match op {
            Modify::Increment(tid) => Ok(MlnrNodeResult::Incremented(
                self.counters[tid].fetch_add(1, Ordering::Relaxed) as u64,
            )),

            Modify::FileOpen(pid, filename, flags, modes) => unimplemented!("File Open"),

            Modify::FileWrite(pid, fd, kernslice, len, offset) => unimplemented!("File Write"),

            Modify::FileClose(pid, fd) => unimplemented!("File Close"),

            Modify::FileDelete(pid, filename) => unimplemented!("File Delete"),

            Modify::FileRename(pid, oldname, newname) => unimplemented!("File Rename"),
        }
    }
}
