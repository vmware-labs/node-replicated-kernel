#![allow(unused)]

use crate::arch::process::UserSlice;
use crate::fs::{FileSystem, FileSystemError, MemNode, Mnode, Modes, NodeType};

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use core::sync::atomic::{AtomicUsize, Ordering};
use custom_error::custom_error;
use hashbrown::HashMap;
use kpi::io::*;
use kpi::SystemCallError;
pub use rwlock::RwLock as NrLock;
use spin::RwLock;

pub mod fd;
mod rwlock;

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

    pub fn create(&self, pathname: &str, modes: Modes) -> Result<u64, FileSystemError> {
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

    pub fn write(
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

    pub fn read(
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

    pub fn lookup(&self, pathname: &str) -> Option<Arc<Mnode>> {
        self.files
            .read()
            .get(&pathname.to_string())
            .map(|mnode| Arc::clone(mnode))
    }

    pub fn file_info(&self, mnode: Mnode) -> FileInfo {
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

    pub fn delete(&self, pathname: &str) -> Result<bool, FileSystemError> {
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

    pub fn truncate(&self, pathname: &str) -> Result<bool, FileSystemError> {
        match self.files.read().get(&pathname.to_string()) {
            Some(mnode) => match self.mnodes.read().get(mnode) {
                Some(memnode) => memnode.write().file_truncate(),
                None => return Err(FileSystemError::InvalidFile),
            },
            None => return Err(FileSystemError::InvalidFile),
        }
    }

    pub fn rename(&self, oldname: &str, newname: &str) -> Result<bool, FileSystemError> {
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
}
