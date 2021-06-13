// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use core::convert::TryFrom;

use kpi::io::FileType;

use crate::arch::process::UserSlice;
use crate::error::KError;
use crate::fallible_string::TryString;

use super::file::*;
use super::{Mnode, Modes};

/// Memnode representation, similar to Inode for a memory-fs.
#[derive(Debug)]
pub struct MemNode {
    mnode_num: Mnode,
    name: String,
    node_type: FileType,
    file: Option<File>,
}

/// Required for the testing
impl PartialEq for MemNode {
    fn eq(&self, other: &Self) -> bool {
        (self.mnode_num == other.mnode_num)
            && (self.name == other.name)
            && (self.node_type == other.node_type)
            && (self.file == other.file)
    }
}

/// Required for the rwlock; not actually used.
impl Default for MemNode {
    fn default() -> MemNode {
        MemNode {
            mnode_num: u64::MAX,
            name: String::new(),
            node_type: FileType::File,
            file: None,
        }
    }
}

impl MemNode {
    /// Initialize a memory-node for a directory or a file.
    pub fn new(
        mnode_num: Mnode,
        pathname: &str,
        modes: Modes,
        node_type: FileType,
    ) -> Result<MemNode, KError> {
        let file = match node_type {
            FileType::Directory => None,
            FileType::File => match File::new(modes) {
                Ok(file) => Some(file),
                Err(e) => return Err(e),
            },
        };

        Ok(MemNode {
            mnode_num,
            name: TryString::try_from(pathname)?.into(),
            node_type,
            file,
        })
    }

    /// Write to an in-memory file.
    pub fn write(&mut self, buffer: &[u8], offset: usize) -> Result<usize, KError> {
        // Return if the user doesn't have write permissions for the file.
        if self.node_type != FileType::File || !self.file.as_ref().unwrap().get_mode().is_writable()
        {
            return Err(KError::PermissionError);
        }
        let len: usize = buffer.len();

        self.file.as_mut().unwrap().write_file(buffer, len, offset)
    }

    /// Read from an in-memory file.
    pub fn read(&self, buffer: &mut UserSlice, offset: usize) -> Result<usize, KError> {
        // Return if the user doesn't have read permissions for the file.
        if self.node_type != FileType::File || !self.file.as_ref().unwrap().get_mode().is_readable()
        {
            return Err(KError::PermissionError);
        }

        let len: usize = buffer.len();
        let file_size = self.get_file_size();
        if offset > file_size {
            return Ok(0);
        }

        let bytes_to_read = core::cmp::min(file_size - offset, len);
        let new_offset = offset + bytes_to_read;

        if bytes_to_read == 0 {
            return Ok(0);
        }
        // Return error if start-offset is greater than or equal to new-offset OR
        // new offset is greater than the file size.
        if offset >= new_offset || new_offset > self.get_file_size() as usize {
            return Err(KError::InvalidOffset);
        }

        // Read from file only if its not at EOF.
        self.file
            .as_ref()
            .unwrap()
            .read_file(&mut *buffer, offset, new_offset)
    }

    /// Get the file size
    pub fn get_file_size(&self) -> usize {
        self.file.as_ref().unwrap().get_size()
    }

    /// Get the type of mnode; Directory or file.
    pub fn get_mnode_type(&self) -> FileType {
        self.node_type
    }

    /// Truncate the file in reasponse of O_TRUNC flag.
    pub fn file_truncate(&mut self) -> Result<(), KError> {
        if self.node_type != FileType::File || !self.file.as_ref().unwrap().get_mode().is_writable()
        {
            return Err(KError::PermissionError);
        }

        // The method doesn't fail after this point, so returning Ok().
        self.file.as_mut().unwrap().file_truncate();
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use alloc::string::ToString;
    use kpi::io::*;

    #[test]
    /// Create mnode directory and verify the values.
    fn test_mnode_directory() {
        let filename = "dir";
        let memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::Directory).unwrap();
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::Directory);
    }

    #[test]
    /// Create mnode file and verify the values.
    fn test_mnode_file() {
        let filename = "file.txt";
        let memnode = MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::File);
    }

    #[test]
    fn test_mnode_write_directory() {
        let filename = "dir";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::Directory).unwrap();
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::Directory);
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0), Err(KError::PermissionError));
    }

    #[test]
    /// Write to mnode file and verify the values.
    fn test_mnode_file_write() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::File);
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);
    }

    #[test]
    /// Write to mnode file which doesn't have write permissions.
    fn test_mnode_file_write_permission_error() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRUSR.into(), FileType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRUSR.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::File);
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0), Err(KError::PermissionError));
    }

    #[test]
    /// Read from mnode file.
    fn test_mnode_file_read() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::File);
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);
        let buffer: &mut [u8; 10] = &mut [0; 10];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 10), 0)
                .unwrap(),
            10
        );
        assert_eq!(buffer[0], 0xb);
        assert_eq!(buffer[9], 0xb);
    }

    #[test]
    /// Read from mnode file which doesn't have read permissions.
    fn test_mnode_file_read_permission_error() {
        let filename = "file.txt";
        let memnode = MemNode::new(1, filename, FileModes::S_IWUSR.into(), FileType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IWUSR.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, FileType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode.read(&mut UserSlice::new(buffer.as_ptr() as u64, 10), 0),
            Err(KError::PermissionError)
        );
    }

    #[test]
    /// Test if the offset is updated properly.
    fn test_offset_tracking() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);

        for i in 0..10 {
            //assert_eq!(i, memnode.offset.load(Ordering::Relaxed));
            let buffer: &mut [u8; 1] = &mut [0; 1];
            assert_eq!(
                memnode
                    .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 0)
                    .unwrap(),
                1
            );
            assert_eq!(buffer[0], 0xb);
        }

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 10)
                .unwrap(),
            0
        );
        assert_eq!(buffer[0], 0);
    }

    #[test]
    /// Test reading the file at a given offset.
    fn test_read_at_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 9)
                .unwrap(),
            1
        );
        assert_eq!(buffer[0], 0xb);

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 10)
                .unwrap(),
            0
        );
        assert_eq!(buffer[0], 0);
    }

    #[test]
    /// Test reading the file at a given offset at EOF.
    fn test_read_at_eof_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 10)
                .unwrap(),
            0
        );
        assert_eq!(buffer[0], 0);
        //assert_eq!(0, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test writing the file at the given offset.
    fn test_write_at_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);
        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);

        let rbuffer: &mut [u8; 10] = &mut [0; 10];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(rbuffer.as_ptr() as u64, 10), 0)
                .unwrap(),
            10
        );
        assert_eq!(rbuffer[0], 0xb);
        assert_eq!(rbuffer[9], 0xb);
        assert_eq!(10, memnode.get_file_size());
    }

    #[test]
    /// Test writing the file at the given offset.
    fn test_write_at_eof_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        let buffer: &mut [u8; 10] = &mut [0xb; 10];
        let rbuffer: &mut [u8; 20] = &mut [0; 20];

        assert_eq!(memnode.write(buffer, 0).unwrap(), 10);
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(rbuffer.as_ptr() as u64, 10), 0)
                .unwrap(),
            10
        );
        assert_eq!(rbuffer[0], 0xb);
        assert_eq!(rbuffer[9], 0xb);

        // This will fill the file between EOF and offset with zeros
        assert_eq!(memnode.write(buffer, 20).unwrap(), 10);
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(rbuffer.as_ptr() as u64, 20), 10)
                .unwrap(),
            20
        );
        assert_eq!(rbuffer[0], 0);
        assert_eq!(rbuffer[9], 0);
        assert_eq!(rbuffer[10], 0xb);
        assert_eq!(rbuffer[19], 0xb);
        assert_eq!(30, memnode.get_file_size());
    }

    #[test]
    /// Test file_truncate for writable file; should succeed.
    fn test_file_truncate_for_writable_file() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::File).unwrap();
        assert_eq!(memnode.file_truncate(), Ok(()));
    }

    #[test]
    /// Test file_truncate for writable directory; should fail.
    fn test_file_truncate_for_writable_directory() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), FileType::Directory).unwrap();
        assert_eq!(memnode.file_truncate(), Err(KError::PermissionError));
    }

    #[test]
    /// Test file_truncate for readable file; should fail.
    fn test_file_truncate_for_nonwritable_file() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRUSR.into(), FileType::File).unwrap();
        assert_eq!(memnode.file_truncate(), Err(KError::PermissionError));
    }
}
