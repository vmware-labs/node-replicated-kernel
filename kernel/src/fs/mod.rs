//! The core module for file management.

mod file;
mod name;

use alloc::string::String;
use alloc::string::ToString;
use core::sync::atomic::{AtomicUsize, Ordering};
use cstr_core::CStr;
use hashbrown::HashMap;
use x86::bits64::paging::VAddr;

use crate::arch::process::UserPtr;
use crate::fs::file::{MemNode, NodeType};

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
        Fd { mnode: 1, flags: 2 }
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
    /// Initialize the file system from the root directory.
    pub fn init() -> MemFS {
        let rootdir = "/";
        let rootmnode = 1;

        let mut mnodes = HashMap::new();
        mnodes.insert(
            rootmnode,
            MemNode::new(rootmnode, rootdir, 0, NodeType::Directory),
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

    /// Get the next available memnode number.
    fn get_next_mno(&mut self) -> usize {
        self.nextmemnode.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a file in the root directory.
    pub fn create(&mut self, pathname: Filename, modes: Modes) -> u64 {
        let mut user_ptr = VAddr::from(pathname);
        let str_ptr = UserPtr::new(&mut user_ptr);

        // TODO: Assume that all files are in the root directory.
        // Later, parse the full path into directory and file.
        let filename;
        unsafe {
            match CStr::from_ptr(str_ptr.as_mut_ptr()).to_str() {
                Ok(path) => {
                    filename = path;
                }
                Err(_) => unreachable!("FileCreate: Unable to convert u64 to str"),
            }
        }

        let mnode_num = self.get_next_mno() as u64;
        let memnode = MemNode::new(mnode_num, filename, modes, NodeType::File);
        self.files.insert(filename.to_string(), mnode_num);
        self.mnodes.insert(mnode_num, memnode);

        mnode_num
    }

    /// Write data to a file.
    pub fn write(&mut self, mnode_num: Mnode, buffer: Buffer, len: Len) -> u64 {
        match self.mnodes.get_mut(&mnode_num) {
            Some(mnode) => mnode.write(buffer, len),
            None => 0,
        }
    }

    /// Read data from a file.
    pub fn read(&mut self, mnode_num: Mnode, buffer: Buffer, len: Len) -> u64 {
        match self.mnodes.get_mut(&mnode_num) {
            Some(mnode) => mnode.read(buffer, len),
            None => 0,
        }
    }

    /// Check if a file exists in the file system or not.
    pub fn lookup(&self, pathname: u64) -> (bool, Option<Mnode>) {
        let mut user_ptr = VAddr::from(pathname);
        let str_ptr = UserPtr::new(&mut user_ptr);

        // TODO: Assume that all files are in the root directory.
        // Later, parse the full path into directory and file.
        let filename;
        unsafe {
            match CStr::from_ptr(str_ptr.as_mut_ptr()).to_str() {
                Ok(path) => {
                    filename = path;
                }
                Err(_) => unreachable!("FileCreate: Unable to convert u64 to str"),
            }
        }

        match self.files.get(&filename.to_string()) {
            Some(mnode) => (true, Some(*mnode)),
            None => (false, None),
        }
    }
}
