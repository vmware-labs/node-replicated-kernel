// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(feature = "rackscale")]
use abomonation::{unsafe_abomonate, Abomonation};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::error::KError;

use super::{FileFlags, MnodeNum, MAX_FILES_PER_PROCESS};

/// A user-space file descriptor.
///
/// This type ensures that it's value is never above `MAX_FILES_PER_PROCESS`.
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub(crate) struct FileDescriptor(usize);

#[cfg(feature = "rackscale")]
unsafe_abomonate!(FileDescriptor);

impl FileDescriptor {
    /// Creates a new FileDescriptor.
    ///
    /// # Panics
    /// If argument is above `MAX_FILES_PER_PROCESS`.
    fn new(id: usize) -> Self {
        assert!(id < MAX_FILES_PER_PROCESS);
        Self(id)
    }
}

impl TryFrom<u64> for FileDescriptor {
    type Error = KError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        static_assertions::assert_eq_size!(u64, usize); // If fail, handle below:
        if (value as usize) < MAX_FILES_PER_PROCESS {
            Ok(Self(value as usize))
        } else {
            Err(KError::FileDescriptorTooLarge)
        }
    }
}

impl From<FileDescriptor> for u64 {
    fn from(fd: FileDescriptor) -> Self {
        fd.0 as u64
    }
}

impl From<FileDescriptor> for usize {
    fn from(fd: FileDescriptor) -> Self {
        fd.0
    }
}

pub(super) struct FileDescriptorTable {
    table: arrayvec::ArrayVec<Option<FileDescriptorEntry>, MAX_FILES_PER_PROCESS>,
}

impl Default for FileDescriptorTable {
    fn default() -> Self {
        const NONE_FD: Option<FileDescriptorEntry> = None;
        FileDescriptorTable {
            table: arrayvec::ArrayVec::from([NONE_FD; MAX_FILES_PER_PROCESS]),
        }
    }
}

impl FileDescriptorTable {
    pub(crate) fn allocate_fd(&mut self) -> Option<(FileDescriptor, &mut FileDescriptorEntry)> {
        if let Some(fid) = self.table.iter().position(|fd| fd.is_none()) {
            self.table[fid] = Some(Default::default());
            Some((FileDescriptor::new(fid), self.table[fid].as_mut().unwrap()))
        } else {
            None
        }
    }

    pub(crate) fn deallocate_fd(&mut self, fd: FileDescriptor) -> Result<usize, KError> {
        let idx: usize = fd.into();
        match self.table.get_mut(idx) {
            Some(fdinfo) => match fdinfo {
                Some(_info) => {
                    *fdinfo = None;
                    Ok(idx)
                }
                None => Err(KError::InvalidFileDescriptor),
            },
            None => Err(KError::InvalidFileDescriptor),
        }
    }

    pub(crate) fn get_fd(&self, fd: FileDescriptor) -> Option<&FileDescriptorEntry> {
        let idx: usize = fd.into();
        self.table[idx].as_ref()
    }
}

/// A file descriptor representaion.
#[derive(Debug, Default)]
pub(crate) struct FileDescriptorEntry {
    mnode: MnodeNum,
    flags: FileFlags,
    offset: AtomicUsize,
}

impl FileDescriptorEntry {
    pub(super) fn update(&mut self, mnode: MnodeNum, flags: FileFlags) {
        self.mnode = mnode;
        self.flags = flags;
    }

    pub(super) fn mnode(&self) -> MnodeNum {
        self.mnode
    }

    pub(super) fn flags(&self) -> FileFlags {
        self.flags
    }

    pub(super) fn offset(&self) -> usize {
        self.offset.load(Ordering::Relaxed)
    }

    pub(super) fn update_offset(&self, new_offset: usize) {
        self.offset.store(new_offset, Ordering::Release);
    }
}
