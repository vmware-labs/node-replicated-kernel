// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use crate::arch::process::UserSlice;

use alloc::string::String;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicUsize, Ordering};
use custom_error::custom_error;
use hashbrown::HashMap;
use kpi::io::*;
use kpi::SystemCallError;
use spin::RwLock;

pub use rwlock::RwLock as NrLock;

pub mod fd;

mod file;
mod mnode;
mod rwlock;
#[cfg(test)]
mod test;

use mnode::MemNode;

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

impl From<alloc::collections::TryReserveError> for FileSystemError {
    fn from(_err: alloc::collections::TryReserveError) -> Self {
        FileSystemError::OutOfMemory
    }
}

impl From<core::alloc::AllocError> for FileSystemError {
    fn from(_err: core::alloc::AllocError) -> Self {
        FileSystemError::OutOfMemory
    }
}

impl From<hashbrown::TryReserveError> for FileSystemError {
    fn from(_err: hashbrown::TryReserveError) -> Self {
        FileSystemError::OutOfMemory
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
    fn delete(&self, pathname: &str) -> Result<(), FileSystemError>;
    fn truncate(&self, pathname: &str) -> Result<(), FileSystemError>;
    fn rename(&self, oldname: &str, newname: &str) -> Result<(), FileSystemError>;
    fn mkdir(&self, pathname: &str, modes: Modes) -> Result<(), FileSystemError>;
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
        self.mnode
    }

    fn get_flags(&self) -> FileFlags {
        self.flags
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
        // Note: Alloc errors are currently ok in this function since this
        // happens during system initialization
        use alloc::string::ToString;

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
                    FileType::Directory,
                )
                .unwrap(),
            ),
        );
        let mut files = RwLock::new(HashMap::new());
        files.write().insert(
            rootdir.to_string(),
            Arc::try_new(1).expect("Not enough memory to initialize system"),
        );
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

/// Helper function for fallible string (paths) allocation
///
/// TODO(api): This should probably go into a FallibleString trait.
fn try_make_path(path: &str) -> Result<String, alloc::collections::TryReserveError> {
    // let newname_key = newname.to_string();
    let mut new_string = String::new();
    new_string.try_reserve(path.len())?;
    new_string.push_str(path);
    Ok(new_string)
}

impl FileSystem for MlnrFS {
    fn create(&self, pathname: &str, modes: Modes) -> Result<u64, FileSystemError> {
        // Check if the file with the same name already exists.
        if self.files.read().get(pathname).is_some() {
            return Err(FileSystemError::AlreadyPresent);
        }
        let pathname_string = try_make_path(pathname)?;

        let mnode_num = self.get_next_mno() as u64;
        // TODO(error-handling): can we ignore or should we decrease mnode_num
        // on error?
        let arc_mnode_num = Arc::try_new(mnode_num)?;
        let mut mnodes = self.mnodes.write();
        mnodes.try_reserve(1)?;

        // TODO: For now all newly created mnode are for file. How to differentiate
        // between a file and a directory. Take input from the user?
        let memnode = MemNode::new(mnode_num, pathname, modes, FileType::File)?;

        self.files.write().insert(pathname_string, arc_mnode_num);
        mnodes.insert(mnode_num, NrLock::new(memnode));

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
        self.files.read().get(pathname).cloned()
    }

    fn file_info(&self, mnode: Mnode) -> FileInfo {
        match self.mnodes.read().get(&mnode) {
            Some(mnode) => match mnode.read().get_mnode_type() {
                FileType::Directory => FileInfo {
                    fsize: 0,
                    ftype: FileType::Directory.into(),
                },
                FileType::File => FileInfo {
                    fsize: mnode.read().get_file_size() as u64,
                    ftype: FileType::File.into(),
                },
            },
            None => unreachable!("file_info: shouldn't reach here"),
        }
    }

    fn delete(&self, pathname: &str) -> Result<(), FileSystemError> {
        let mut files = self.files.write();
        if let Some(mnode) = files.get(pathname) {
            if Arc::strong_count(mnode) == 1 {
                self.mnodes.write().remove(&mnode);
            } else {
                return Err(FileSystemError::PermissionError);
            }
        } else {
            return Err(FileSystemError::InvalidFile);
        }

        let r = files.remove(pathname);
        assert!(r.is_some(), "Didn't remove the mnode?");
        Ok(())
    }

    fn truncate(&self, pathname: &str) -> Result<(), FileSystemError> {
        match self.files.read().get(pathname) {
            Some(mnode) => match self.mnodes.read().get(mnode) {
                Some(memnode) => memnode.write().file_truncate(),
                None => Err(FileSystemError::InvalidFile),
            },
            None => Err(FileSystemError::InvalidFile),
        }
    }

    fn rename(&self, oldname: &str, newname: &str) -> Result<(), FileSystemError> {
        if self.files.read().get(oldname).is_none() {
            return Err(FileSystemError::InvalidFile);
        }
        let mut newname_key = try_make_path(newname)?;

        // If the newfile exists then overwrite it with the oldfile.
        if self.files.read().get(newname).is_some() {
            self.delete(newname).unwrap();
        }

        // TODO: Can we optimize it somehow?
        let mut lock_at_root = self.files.write();
        match lock_at_root.remove_entry(oldname) {
            Some((_key, oldnmode)) => match lock_at_root.insert(newname_key, oldnmode) {
                None => Ok(()),
                Some(_) => Err(FileSystemError::PermissionError),
            },
            None => Err(FileSystemError::InvalidFile),
        }
    }

    /// Create a directory. The implementation is quite simplistic for now, and only used
    /// by leveldb benchmark.
    fn mkdir(&self, pathname: &str, modes: Modes) -> Result<(), FileSystemError> {
        // Check if the file with the same name already exists.
        if self.files.read().get(pathname).is_some() {
            return Err(FileSystemError::AlreadyPresent);
        }

        let pathname_key = try_make_path(pathname)?;
        let mnode_num = self.get_next_mno() as u64;
        // TODO(error-handling): Should we decrease mnode-num or ignore?
        let arc_mnode_num = Arc::try_new(mnode_num)?;
        let mut mnodes = self.mnodes.write();
        mnodes.try_reserve(1)?;

        let memnode = match MemNode::new(mnode_num, pathname, modes, FileType::Directory) {
            Ok(memnode) => memnode,
            Err(e) => return Err(e),
        };
        self.files.write().insert(pathname_key, arc_mnode_num);
        mnodes.insert(mnode_num, NrLock::new(memnode));

        Ok(())
    }
}
