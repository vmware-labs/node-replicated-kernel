// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{Fd, FileDescriptor, MAX_FILES_PER_PROCESS};
use arr_macro::arr;

pub struct FileDesc {
    fds: arrayvec::ArrayVec<[Option<Fd>; MAX_FILES_PER_PROCESS]>,
}

impl Default for FileDesc {
    fn default() -> Self {
        FileDesc {
            fds: arrayvec::ArrayVec::from(arr![None; 4096]), // MAX_FILES_PER_PROCESS
        }
    }
}

impl FileDesc {
    pub fn allocate_fd(&mut self) -> Option<(u64, &mut Fd)> {
        let mut fd: i64 = -1;
        for i in 0..MAX_FILES_PER_PROCESS {
            match self.fds[i] {
                None => {
                    fd = i as i64;
                    break;
                }
                _ => continue,
            }
        }

        match fd {
            -1 => None,
            f => {
                let filedesc = Fd::init_fd();
                self.fds[f as usize] = Some(Default::default());
                Some((f as u64, self.fds[f as usize].as_mut().unwrap()))
            }
        }
    }

    pub fn deallocate_fd(&mut self, fd: usize) -> usize {
        let is_fd = {
            if fd < MAX_FILES_PER_PROCESS && self.fds[fd].is_some() {
                true
            } else {
                false
            }
        };

        if is_fd {
            self.fds[fd] = None;
            return fd;
        }
        MAX_FILES_PER_PROCESS + 1
    }

    pub fn get_fd(&self, index: usize) -> Option<&Fd> {
        self.fds[index].as_ref()
    }
}
