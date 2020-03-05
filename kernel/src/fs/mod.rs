//! The core module for file management.

use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicUsize, Ordering};

use custom_error::custom_error;
use hashbrown::HashMap;

use kpi::io::*;
use kpi::SystemCallError;

use crate::fs::mnode::{MemNode, NodeType};

mod mnode;
#[cfg(test)]
mod test;

/// The maximum number of open files for a process.
pub const MAX_FILES_PER_PROCESS: usize = 8;

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
    fn create(&mut self, pathname: &str, modes: Modes) -> Option<u64>;
    fn write(&mut self, mnode_num: Mnode, buffer: Buffer, len: Len, offset: Offset) -> u64;
    fn read(&self, mnode_num: Mnode, buffer: Buffer, len: Len, offset: Offset) -> u64;
    fn lookup(&self, pathname: &str) -> (bool, Option<Mnode>);
    fn file_info(&self, mnode: Mnode) -> (u64, u64);
}

/// Abstract definition of a file descriptor.
pub trait FileDescriptor {
    fn init_fd() -> Fd;
    fn update_fd(&mut self, mnode: Mnode, flags: Flags);
    fn get_mnode(&self) -> Mnode;
    fn get_flags(&self) -> Flags;
}

/// A file descriptor representation.
#[derive(Debug, Default)]
pub struct Fd {
    mnode: Mnode,
    flags: Flags,
}

impl FileDescriptor for Fd {
    fn init_fd() -> Fd {
        Fd {
            // Intial values are just the place-holders and shouldn't be used.
            mnode: core::u64::MAX,
            flags: 0,
        }
    }

    fn update_fd(&mut self, mnode: Mnode, flags: Flags) {
        self.mnode = mnode;
        self.flags = flags;
    }

    fn get_mnode(&self) -> Mnode {
        self.mnode.clone()
    }

    fn get_flags(&self) -> Flags {
        self.flags.clone()
    }
}

/// The in-memory file-system representation.
#[derive(Debug)]
pub struct MemFS {
    mnodes: HashMap<Mnode, MemNode>,
    files: HashMap<String, Mnode>,
    root: (String, Mnode),
    nextmemnode: AtomicUsize,
}

impl MemFS {
    /// Get the next available memnode number.
    fn get_next_mno(&mut self) -> usize {
        self.nextmemnode.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for MemFS {
    /// Initialize the file system from the root directory.
    fn default() -> MemFS {
        let rootdir = "/";
        let rootmnode = 1;

        let mut mnodes = HashMap::new();
        mnodes.insert(
            rootmnode,
            MemNode::new(rootmnode, rootdir, ALL_PERM, NodeType::Directory),
        );
        let mut files = HashMap::new();
        files.insert(rootdir.to_string(), 1);
        let root = (rootdir.to_string(), 1);

        MemFS {
            mnodes,
            files,
            root,
            nextmemnode: AtomicUsize::new(2),
        }
    }
}

impl FileSystem for MemFS {
    /// Create a file relative to the root directory.
    fn create(&mut self, pathname: &str, modes: Modes) -> Option<u64> {
        // Check if the file with the same name already exists.
        match self.files.get(&pathname.to_string()) {
            Some(_) => return None,
            None => {}
        }

        let mnode_num = self.get_next_mno() as u64;
        //TODO: For now all newly created mnode are for file. How to differentiate
        // between a file and a directory. Take input from the user?
        let memnode = MemNode::new(mnode_num, pathname, modes, NodeType::File);
        self.files.insert(pathname.to_string(), mnode_num);
        self.mnodes.insert(mnode_num, memnode);

        Some(mnode_num)
    }

    /// Write data to a file.
    fn write(&mut self, mnode_num: Mnode, buffer: Buffer, len: Len, offset: Offset) -> u64 {
        match self.mnodes.get_mut(&mnode_num) {
            Some(mnode) => mnode.write(buffer, len, offset),
            None => 0,
        }
    }

    /// Read data from a file.
    fn read(&self, mnode_num: Mnode, buffer: Buffer, len: Len, offset: Offset) -> u64 {
        match self.mnodes.get(&mnode_num) {
            Some(mnode) => mnode.read(buffer, len, offset),
            None => 0,
        }
    }

    /// Check if a file exists in the file system or not.
    fn lookup(&self, pathname: &str) -> (bool, Option<Mnode>) {
        match self.files.get(&pathname.to_string()) {
            Some(mnode) => (true, Some(*mnode)),
            None => (false, None),
        }
    }

    /// Find the size and type by giving the mnode number.
    fn file_info(&self, mnode: Mnode) -> (u64, u64) {
        match self.mnodes.get(&mnode) {
            Some(mnode) => match mnode.get_mnode_type() {
                NodeType::Directory => (0, NodeType::Directory.into()),
                NodeType::File => (mnode.get_file_size(), NodeType::File.into()),
            },
            None => unreachable!("file_info: shouldn't reach here"),
        }
    }
}
