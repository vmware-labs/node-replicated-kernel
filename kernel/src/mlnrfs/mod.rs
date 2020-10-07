use crate::arch::process::UserSlice;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use custom_error::custom_error;
use hashbrown::HashMap;

pub use crate::fs::{
    Buffer, FileSystem, FileSystemError, Filename, Flags, Len, Mnode, Modes, Offset, FD,
};
use kpi::io::*;
use kpi::SystemCallError;

pub struct MlnrFS {
    pub counter: AtomicUsize,
}

impl Default for MlnrFS {
    fn default() -> Self {
        MlnrFS {
            counter: AtomicUsize::new(0),
        }
    }
}

impl MlnrFS {}

impl FileSystem for MlnrFS {
    fn create(&mut self, pathname: &str, modes: Modes) -> Result<u64, FileSystemError> {
        unimplemented!("create");
    }

    fn write(
        &mut self,
        mnode_num: Mnode,
        buffer: &[u8],
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        unimplemented!("write");
    }

    fn read(
        &self,
        mnode_num: Mnode,
        buffer: &mut UserSlice,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        unimplemented!("read");
    }

    fn lookup(&self, pathname: &str) -> Option<Arc<Mnode>> {
        unimplemented!("lookup");
    }

    fn file_info(&self, mnode: Mnode) -> FileInfo {
        unimplemented!("file_info");
    }

    fn delete(&mut self, pathname: &str) -> Result<bool, FileSystemError> {
        unimplemented!("delete");
    }

    fn truncate(&mut self, pathname: &str) -> Result<bool, FileSystemError> {
        unimplemented!("truncate");
    }

    fn rename(&mut self, oldname: &str, newname: &str) -> Result<bool, FileSystemError> {
        unimplemented!("rename");
    }
}
