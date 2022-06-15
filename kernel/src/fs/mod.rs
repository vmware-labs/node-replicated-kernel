// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use alloc::sync::Arc;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashMap;
use kpi::io::*;
use spin::RwLock;

use crate::error::KError;
use crate::fallible_string::TryString;
use crate::process::SliceAccess;

pub(crate) use rwlock::RwLock as NrLock;

pub mod cnrfs;
pub mod fd;

mod file;
mod mnode;
mod rwlock;
#[cfg(test)]
mod test;

use mnode::MemNode;

/// The maximum number of open files for a process.
pub(crate) const MAX_FILES_PER_PROCESS: usize = 4096;

/// Mnode number.
pub(crate) type MnodeNum = u64;

/// Abstract definition of file-system interface operations.
pub(crate) trait FileSystem {
    fn create(&self, pathname: String, modes: FileModes) -> Result<u64, KError>;
    fn write(&self, mnode_num: MnodeNum, buffer: &[u8], offset: usize) -> Result<usize, KError>;
    fn read(
        &self,
        mnode_num: MnodeNum,
        buffer: &mut dyn SliceAccess,
        offset: usize,
    ) -> Result<usize, KError>;
    fn lookup(&self, pathname: &str) -> Option<Arc<MnodeNum>>;
    fn file_info(&self, mnode: MnodeNum) -> FileInfo;
    fn delete(&self, pathname: &str) -> Result<(), KError>;
    fn truncate(&self, pathname: &str) -> Result<(), KError>;
    fn rename(&self, oldname: &str, newname: String) -> Result<(), KError>;
    fn mkdir(&self, pathname: String, modes: FileModes) -> Result<(), KError>;
}

/// The mnode number assigned to the first file.
pub(crate) const MNODE_OFFSET: usize = 2;

/// The in-memory file-system representation.
#[derive(Debug)]
pub(crate) struct MlnrFS {
    /// Only create file will lock the hashmap in write mode,
    /// every other operation is locked in read mode.
    mnodes: NrLock<HashMap<MnodeNum, NrLock<MemNode>>>,
    files: RwLock<HashMap<String, Arc<MnodeNum>>>,
    _root: (String, MnodeNum),
    nextmemnode: AtomicUsize,
}

unsafe impl Sync for MlnrFS {}

impl Default for MlnrFS {
    /// Initialize the file system from the root directory.
    fn default() -> MlnrFS {
        let rootdir = "/";
        let rootmnode = 1;

        let mnodes = NrLock::<HashMap<MnodeNum, NrLock<MemNode>>>::default();
        mnodes.write().insert(
            rootmnode,
            NrLock::new(
                MemNode::new(rootmnode, rootdir, FileModes::S_IRWXU, FileType::Directory).unwrap(),
            ),
        );
        let files = RwLock::new(HashMap::new());
        files.write().insert(
            TryString::try_from(rootdir)
                .expect("Not enough memory to initialize system")
                .into(),
            Arc::try_new(1).expect("Not enough memory to initialize system"),
        );
        let root = (
            TryString::try_from(rootdir)
                .expect("Not enough memory to initialize system")
                .into(),
            1,
        );

        MlnrFS {
            mnodes,
            files,
            _root: root,
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
    fn create(&self, pathname: String, modes: FileModes) -> Result<u64, KError> {
        // Check if the file with the same name already exists.
        if self.files.read().get(&pathname).is_some() {
            return Err(KError::AlreadyPresent);
        }

        let mnode_num = self.get_next_mno() as u64;
        // TODO(error-handling): can we ignore or should we decrease mnode_num
        // on error?
        let arc_mnode_num = Arc::try_new(mnode_num)?;
        let mut mnodes = self.mnodes.write();
        mnodes.try_reserve(1)?;

        // TODO: For now all newly created mnode are for file. How to differentiate
        // between a file and a directory. Take input from the user?
        let memnode = MemNode::new(mnode_num, &pathname, modes, FileType::File)?;

        self.files.write().insert(pathname, arc_mnode_num);
        mnodes.insert(mnode_num, NrLock::new(memnode));

        Ok(mnode_num)
    }

    fn write(&self, mnode_num: MnodeNum, buffer: &[u8], offset: usize) -> Result<usize, KError> {
        match self.mnodes.read().get(&mnode_num) {
            Some(mnode) => mnode.write().write(buffer, offset),
            None => Err(KError::InvalidFile),
        }
    }

    fn read(
        &self,
        mnode_num: MnodeNum,
        buffer: &mut dyn SliceAccess,
        offset: usize,
    ) -> Result<usize, KError> {
        match self.mnodes.read().get(&mnode_num) {
            Some(mnode) => mnode.read().read(buffer, offset),
            None => Err(KError::InvalidFile),
        }
    }

    fn lookup(&self, pathname: &str) -> Option<Arc<MnodeNum>> {
        self.files.read().get(pathname).cloned()
    }

    fn file_info(&self, mnode: MnodeNum) -> FileInfo {
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

    fn delete(&self, pathname: &str) -> Result<(), KError> {
        let mut files = self.files.write();
        if let Some(mnode) = files.get(pathname) {
            if Arc::strong_count(mnode) == 1 {
                self.mnodes.write().remove(mnode);
            } else {
                return Err(KError::PermissionError);
            }
        } else {
            return Err(KError::InvalidFile);
        }

        let r = files.remove(pathname);
        assert!(r.is_some(), "Didn't remove the mnode?");
        Ok(())
    }

    fn truncate(&self, pathname: &str) -> Result<(), KError> {
        match self.files.read().get(pathname) {
            Some(mnode) => match self.mnodes.read().get(mnode) {
                Some(memnode) => memnode.write().file_truncate(),
                None => Err(KError::InvalidFile),
            },
            None => Err(KError::InvalidFile),
        }
    }

    fn rename(&self, oldname: &str, newname: String) -> Result<(), KError> {
        if self.files.read().get(oldname).is_none() {
            return Err(KError::InvalidFile);
        }

        // If the newfile exists then overwrite it with the oldfile.
        if self.files.read().get(&newname).is_some() {
            self.delete(&newname).unwrap();
        }

        // TODO: Can we optimize it somehow?
        let mut lock_at_root = self.files.write();
        match lock_at_root.remove_entry(oldname) {
            Some((_key, oldnmode)) => match lock_at_root.insert(newname, oldnmode) {
                None => Ok(()),
                Some(_) => Err(KError::PermissionError),
            },
            None => Err(KError::InvalidFile),
        }
    }

    /// Create a directory. The implementation is quite simplistic for now, and only used
    /// by leveldb benchmark.
    fn mkdir(&self, pathname: String, modes: FileModes) -> Result<(), KError> {
        // Check if the file with the same name already exists.
        if self.files.read().get(&pathname).is_some() {
            Err(KError::AlreadyPresent)
        } else {
            let mnode_num = self.get_next_mno() as u64;
            // TODO(error-handling): Should we decrease mnode-num or ignore?
            let arc_mnode_num = Arc::try_new(mnode_num)?;
            let mut mnodes = self.mnodes.write();
            mnodes.try_reserve(1)?;
            let memnode = MemNode::new(mnode_num, &pathname, modes, FileType::Directory)?;

            self.files.write().insert(pathname, arc_mnode_num);
            mnodes.insert(mnode_num, NrLock::new(memnode));

            Ok(())
        }
    }
}
