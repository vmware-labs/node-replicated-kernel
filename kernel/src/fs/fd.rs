// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{Fd, MAX_FILES_PER_PROCESS};
use crate::error::KError;

pub struct FileDesc {
    fds: arrayvec::ArrayVec<Option<Fd>, MAX_FILES_PER_PROCESS>,
}

impl Default for FileDesc {
    fn default() -> Self {
        const NONE_FD: Option<Fd> = None;
        FileDesc {
            fds: arrayvec::ArrayVec::from([NONE_FD; MAX_FILES_PER_PROCESS]),
        }
    }
}

impl FileDesc {
    pub fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)> {
        if let Some(fid) = self.fds.iter().position(|fd| fd.is_none()) {
            self.fds[fid] = Some(Default::default());
            Some((fid as u64, self.fds[fid as usize].as_mut().unwrap()))
        } else {
            None
        }
    }

    pub fn deallocate_fd(&mut self, fd: usize) -> Result<usize, KError> {
        match self.fds.get_mut(fd) {
            Some(fdinfo) => match fdinfo {
                Some(info) => {
                    log::debug!("deallocating: {:?}", info);
                    *fdinfo = None;
                    Ok(fd)
                }
                None => Err(KError::InvalidFileDescriptor),
            },
            None => Err(KError::InvalidFileDescriptor),
        }
    }

    pub fn get_fd(&self, index: usize) -> Option<&Fd> {
        self.fds[index].as_ref()
    }
}
