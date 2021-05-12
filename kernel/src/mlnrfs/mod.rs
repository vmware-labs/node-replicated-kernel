// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use crate::arch::process::UserSlice;

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use core::sync::atomic::{AtomicUsize, Ordering};
use custom_error_core::custom_error;
use hashbrown::HashMap;
use kpi::io::*;
use kpi::SystemCallError;
pub use rwlock::RwLock as NrLock;
use spin::RwLock;

pub mod fd;
mod file;
mod mnode;
mod rwlock;
#[cfg(test)]
mod test;

use mnode::{MemNode, NodeType};

/// The maximum number of open files for a process.
pub const MAX_FILES_PER_PROCESS: usize = 4096;

/// Mnode number.
pub type Mnode = u64;
/// Flags for fs calls.
pub type Flags = u64;
/// Modes for fs calls
pub type Modes = u64;
/// File descriptor.
pub type FD = u64;
/// Userspace buffer pointer to read or write a file.
pub type Buffer = u64;
/// Number of bytes to read or write a file.
pub type Len = u64;
/// Userspace-pointer to filename.
pub type Filename = u64;
/// File offset
pub type Offset = i64;

custom_error! {
    #[derive(PartialEq, Clone)]
    pub FileSystemError
    InvalidFileDescriptor = "Supplied file descriptor was invalid",
    InvalidFile = "Supplied file was invalid",
    InvalidFlags = "Supplied flags were invalid",
    InvalidOffset = "Supplied offset was invalid",
    PermissionError = "File/directory can't be read or written",
    AlreadyPresent = "Fd/File already exists",
    DirectoryError = "Can't read or write to a directory",
    OpenFileLimit = "Maximum files are opened for a process",
    OutOfMemory = "Unable to allocate memory for file",
}

impl Into<SystemCallError> for FileSystemError {
    fn into(self) -> SystemCallError {
        match self {
            FileSystemError::InvalidFileDescriptor => SystemCallError::BadFileDescriptor,
            FileSystemError::InvalidFile => SystemCallError::BadFileDescriptor,
            FileSystemError::InvalidFlags => SystemCallError::BadFlags,
            FileSystemError::InvalidOffset => SystemCallError::PermissionError,
            FileSystemError::PermissionError => SystemCallError::PermissionError,
            FileSystemError::AlreadyPresent => SystemCallError::PermissionError,
            FileSystemError::DirectoryError => SystemCallError::PermissionError,
            FileSystemError::OpenFileLimit => SystemCallError::OutOfMemory,
            FileSystemError::OutOfMemory => SystemCallError::OutOfMemory,
        }
    }
}

/// Abstract definition of file-system interface operations.
pub trait FileSystem {
    fn create(&self, pathname: &str, modes: Modes) -> Result<u64, FileSystemError>;
    fn write(
        &self,
        mnode_num: Mnode,
        buffer: &[u8],
        offset: usize,
    ) -> Result<usize, FileSystemError>;
    fn read(
        &self,
        mnode_num: Mnode,
        buffer: &mut UserSlice,
        offset: usize,
    ) -> Result<usize, FileSystemError>;
    fn lookup(&self, pathname: &str) -> Option<Arc<Mnode>>;
    fn file_info(&self, mnode: Mnode) -> FileInfo;
    fn delete(&self, pathname: &str) -> Result<bool, FileSystemError>;
    fn truncate(&self, pathname: &str) -> Result<bool, FileSystemError>;
    fn rename(&self, oldname: &str, newname: &str) -> Result<bool, FileSystemError>;
    fn mkdir(&self, pathname: &str, modes: Modes) -> Result<bool, FileSystemError>;
}

/// Abstract definition of a file descriptor.
pub trait FileDescriptor {
    fn init_fd() -> Fd;
    fn update_fd(&mut self, mnode: Mnode, flags: FileFlags);
    fn get_mnode(&self) -> Mnode;
    fn get_flags(&self) -> FileFlags;
    fn get_offset(&self) -> usize;
    fn update_offset(&self, new_offset: usize);
}

/// A file descriptor representaion.
#[derive(Debug, Default)]
pub struct Fd {
    mnode: Mnode,
    flags: FileFlags,
    offset: AtomicUsize,
}

impl FileDescriptor for Fd {
    fn init_fd() -> Fd {
        Fd {
            // Intial values are just the place-holders and shouldn't be used.
            mnode: u64::MAX,
            flags: Default::default(),
            offset: AtomicUsize::new(0),
        }
    }

    fn update_fd(&mut self, mnode: Mnode, flags: FileFlags) {
        self.mnode = mnode;
        self.flags = flags;
    }

    fn get_mnode(&self) -> Mnode {
        self.mnode.clone()
    }

    fn get_flags(&self) -> FileFlags {
        self.flags.clone()
    }

    fn get_offset(&self) -> usize {
        self.offset.load(Ordering::Relaxed)
    }

    fn update_offset(&self, new_offset: usize) {
        self.offset.store(new_offset, Ordering::Release);
    }
}

/// The mnode number assigned to the first file.
pub const MNODE_OFFSET: usize = 2;

/// The in-memory file-system representation.
#[derive(Debug)]
pub struct MlnrFS {
    /// Only create file will lock the hashmap in write mode,
    /// every other operation is locked in read mode.
    mnodes: NrLock<HashMap<Mnode, NrLock<MemNode>>>,
    files: RwLock<HashMap<String, Arc<Mnode>>>,
    root: (String, Mnode),
    nextmemnode: AtomicUsize,
}

unsafe impl Sync for MlnrFS {}

impl Default for MlnrFS {
    /// Initialize the file system from the root directory.
    fn default() -> MlnrFS {
        let rootdir = "/";
        let rootmnode = 1;

        let mut mnodes = NrLock::<HashMap<Mnode, NrLock<MemNode>>>::default();
        mnodes.write().insert(
            rootmnode,
            NrLock::new(
                MemNode::new(
                    rootmnode,
                    rootdir,
                    FileModes::S_IRWXU.into(),
                    NodeType::Directory,
                )
                .unwrap(),
            ),
        );
        let mut files = RwLock::new(HashMap::new());
        files.write().insert(rootdir.to_string(), Arc::new(1));
        let root = (rootdir.to_string(), 1);

        MlnrFS {
            mnodes,
            files,
            root,
            nextmemnode: AtomicUsize::new(MNODE_OFFSET),
        }
    }
}

impl MlnrFS {
    /// Get the next available memnode number.
    fn get_next_mno(&self) -> usize {
        self.nextmemnode.fetch_add(1, Ordering::Relaxed)
    }
}

impl FileSystem for MlnrFS {
    fn create(&self, pathname: &str, modes: Modes) -> Result<u64, FileSystemError> {
        // Check if the file with the same name already exists.
        match self.files.read().get(&pathname.to_string()) {
            Some(_) => return Err(FileSystemError::AlreadyPresent),
            None => {}
        }

        let mnode_num = self.get_next_mno() as u64;
        //TODO: For now all newly created mnode are for file. How to differentiate
        // between a file and a directory. Take input from the user?
        let memnode = match MemNode::new(mnode_num, pathname, modes, NodeType::File) {
            Ok(memnode) => memnode,
            Err(e) => return Err(e),
        };
        self.files
            .write()
            .insert(pathname.to_string(), Arc::new(mnode_num));
        self.mnodes.write().insert(mnode_num, NrLock::new(memnode));

        Ok(mnode_num)
    }

    fn write(
        &self,
        mnode_num: Mnode,
        buffer: &[u8],
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        match self.mnodes.read().get(&mnode_num) {
            Some(mnode) => mnode.write().write(buffer, offset),
            None => Err(FileSystemError::InvalidFile),
        }
    }

    fn read(
        &self,
        mnode_num: Mnode,
        buffer: &mut UserSlice,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        match self.mnodes.read().get(&mnode_num) {
            Some(mnode) => mnode.read().read(buffer, offset),
            None => Err(FileSystemError::InvalidFile),
        }
    }

    fn lookup(&self, pathname: &str) -> Option<Arc<Mnode>> {
        self.files
            .read()
            .get(&pathname.to_string())
            .map(|mnode| Arc::clone(mnode))
    }

    fn file_info(&self, mnode: Mnode) -> FileInfo {
        match self.mnodes.read().get(&mnode) {
            Some(mnode) => match mnode.read().get_mnode_type() {
                NodeType::Directory => FileInfo {
                    fsize: 0,
                    ftype: NodeType::Directory.into(),
                },
                NodeType::File => FileInfo {
                    fsize: mnode.read().get_file_size() as u64,
                    ftype: NodeType::File.into(),
                },
            },
            None => unreachable!("file_info: shouldn't reach here"),
        }
    }

    fn delete(&self, pathname: &str) -> Result<bool, FileSystemError> {
        match self.files.write().remove(&pathname.to_string()) {
            Some(mnode) => {
                // If the pathname is the only link to the memnode, then remove it.
                match Arc::strong_count(&mnode) {
                    1 => {
                        self.mnodes.write().remove(&mnode);
                        return Ok(true);
                    }
                    _ => {
                        self.files.write().insert(pathname.to_string(), mnode);
                        return Err(FileSystemError::PermissionError);
                    }
                }
            }
            None => return Err(FileSystemError::InvalidFile),
        };
    }

    fn truncate(&self, pathname: &str) -> Result<bool, FileSystemError> {
        match self.files.read().get(&pathname.to_string()) {
            Some(mnode) => match self.mnodes.read().get(mnode) {
                Some(memnode) => memnode.write().file_truncate(),
                None => return Err(FileSystemError::InvalidFile),
            },
            None => return Err(FileSystemError::InvalidFile),
        }
    }

    fn rename(&self, oldname: &str, newname: &str) -> Result<bool, FileSystemError> {
        if self.files.read().get(oldname).is_none() {
            return Err(FileSystemError::InvalidFile);
        }

        // If the newfile exists then overwrite it with the oldfile.
        if self.files.read().get(newname).is_some() {
            self.delete(newname).unwrap();
        }

        // TODO: Can we optimize it somehow?
        let mut lock_at_root = self.files.write();
        match lock_at_root.remove_entry(oldname) {
            Some((_key, oldnmode)) => match lock_at_root.insert(newname.to_string(), oldnmode) {
                None => return Ok(true),
                Some(_) => return Err(FileSystemError::PermissionError),
            },
            None => Err(FileSystemError::InvalidFile),
        }
    }

    /// Create a directory. The implementation is quite simplistic for now, and only used
    /// by leveldb benchmark.
    fn mkdir(&self, pathname: &str, modes: Modes) -> Result<bool, FileSystemError> {
        // Check if the file with the same name already exists.
        match self.files.read().get(&pathname.to_string()) {
            Some(_) => return Err(FileSystemError::AlreadyPresent),
            None => {}
        }

        let mnode_num = self.get_next_mno() as u64;
        let memnode = match MemNode::new(mnode_num, pathname, modes, NodeType::Directory) {
            Ok(memnode) => memnode,
            Err(e) => return Err(e),
        };
        self.files
            .write()
            .insert(pathname.to_string(), Arc::new(mnode_num));
        self.mnodes.write().insert(mnode_num, NrLock::new(memnode));

        Ok(true)
    }
}
