use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use kpi::io::*;
use x86::bits64::paging::VAddr;

use crate::arch::process::{UserPtr, UserValue};
use crate::fs::file::*;
use crate::fs::{Mnode, Modes};

/// Each memory-node can be of two types: directory or a file.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u64)]
pub enum NodeType {
    /// The mnode is of directory type
    Directory = 1,
    /// The mnode is of regular type
    File = 2,
}

impl Into<u64> for NodeType {
    fn into(self) -> u64 {
        match self {
            NodeType::Directory => 1,
            NodeType::File => 2,
        }
    }
}

/// Memnode representation, similar to Inode for a memory-fs.
#[derive(Debug)]
pub struct MemNode {
    mnode_num: Mnode,
    name: String,
    node_type: NodeType,
    file: Option<File>,
    offset: AtomicUsize,
}

/// Required for the testing
impl PartialEq for MemNode {
    fn eq(&self, other: &Self) -> bool {
        (self.mnode_num == other.mnode_num)
            && (self.name == other.name)
            && (self.node_type == other.node_type)
            && (self.file == other.file)
            && (self.offset.load(Ordering::Relaxed) == other.offset.load(Ordering::Relaxed))
    }
}

impl MemNode {
    /// Initialize a memory-node for a directory or a file.
    pub fn new(mnode_num: Mnode, pathname: &str, modes: Modes, node_type: NodeType) -> MemNode {
        let file = match node_type {
            NodeType::Directory => None,
            NodeType::File => Some(File::new(modes)),
        };

        MemNode {
            mnode_num,
            name: pathname.to_string(),
            node_type,
            file,
            offset: AtomicUsize::new(0),
        }
    }

    /// Write to an in-memory file.
    pub fn write(&mut self, buffer: u64, len: u64, offset: i64) -> u64 {
        // Return if the user doesn't have write permissions for the file.
        if self.node_type != NodeType::File
            || !is_allowed!(self.file.as_ref().unwrap().get_mode(), S_IWUSR)
        {
            return 0;
        }
        let buffer: *const u8 = buffer as *const u8;
        let len: usize = len as usize;

        let user_slice = unsafe { &mut core::slice::from_raw_parts(buffer, len) };
        let userval = UserValue::new(user_slice);

        match self
            .file
            .as_mut()
            .unwrap()
            .write_file(&mut userval.to_vec(), len, offset)
        {
            Ok(len) => len as u64,
            Err(_) => 0,
        }
    }

    /// Read from an in-memory file.
    pub fn read(&self, buffer: u64, len: u64, offset: i64) -> u64 {
        let modes = self.file.as_ref().unwrap().get_mode();
        // Return if the user doesn't have read permissions for the file.
        if !is_allowed!(modes, S_IRUSR) {
            return 0;
        }

        let len: usize = len as usize;
        let file_size = self.get_file_size();

        // If offset is specified and its less than the file size,
        // then update the current offset.
        if (offset != -1) && (offset as usize) <= file_size {
            self.update_offset(offset as usize);
        }
        let file_offset = self.offset.load(Ordering::Relaxed);
        let bytes_to_read = core::cmp::min(file_size - file_offset, len);
        let new_offset = file_offset + bytes_to_read;

        // Read from file only if its not at EOF.
        if new_offset > file_offset {
            let mut user_ptr = VAddr::from(buffer);
            let slice_ptr = UserPtr::new(&mut user_ptr);
            let user_slice: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
            match self
                .file
                .as_ref()
                .unwrap()
                .read_file(user_slice, file_offset, new_offset)
            {
                Ok(len) => {
                    self.update_offset(file_offset + len);
                    return len as u64;
                }
                Err(_) => return 0,
            }
        }
        return 0;
    }

    /// Update the offset after reading the file.
    fn update_offset(&self, new_offset: usize) -> bool {
        if new_offset <= self.get_file_size() as usize {
            self.offset.store(new_offset, Ordering::Release);
            return true;
        }
        false
    }

    /// Get the file size
    pub fn get_file_size(&self) -> usize {
        self.file.as_ref().unwrap().get_size()
    }

    /// Get the type of mnode; Directory or file.
    pub fn get_mnode_type(&self) -> NodeType {
        self.node_type
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    /// Create mnode directory and verify the values.
    fn test_mnode_directory() {
        let filename = "dir";
        let memnode = MemNode::new(1, filename, ALL_PERM, NodeType::Directory);
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::Directory);
    }

    #[test]
    /// Create mnode file and verify the values.
    fn test_mnode_file() {
        let filename = "file.txt";
        let memnode = MemNode::new(1, filename, ALL_PERM, NodeType::File);
        assert_eq!(memnode.file, Some(File::new(ALL_PERM)));
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
    }

    #[test]
    fn test_mnode_write_directory() {
        let filename = "dir";
        let mut memnode = MemNode::new(1, filename, ALL_PERM, NodeType::Directory);
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::Directory);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 0);
    }

    #[test]
    /// Write to mnode file and verify the values.
    fn test_mnode_file_write() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, ALL_PERM, NodeType::File);
        assert_eq!(memnode.file, Some(File::new(ALL_PERM)));
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);
    }

    #[test]
    /// Write to mnode file which doesn't have write permissions.
    fn test_mnode_file_write_permission_error() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRUSR, NodeType::File);
        assert_eq!(memnode.file, Some(File::new(S_IRUSR)));
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 0);
    }

    #[test]
    /// Read from mnode file.
    fn test_mnode_file_read() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        assert_eq!(memnode.file, Some(File::new(S_IRWXU)));
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);
        let buffer: &mut [u8; 10] = &mut [0; 10];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 10, -1), 10);
        assert_eq!(buffer[0], 0xb);
        assert_eq!(buffer[9], 0xb);
    }

    #[test]
    /// Read from mnode file which doesn't have read permissions.
    fn test_mnode_file_read_permission_error() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IWUSR, NodeType::File);
        assert_eq!(memnode.file, Some(File::new(S_IWUSR)));
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 10, -1), 0);
    }

    #[test]
    /// Test update offset method
    fn test_update_offset() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IWUSR, NodeType::File);
        assert_eq!(false, memnode.update_offset(10));
        assert_eq!(true, memnode.update_offset(0));
        assert_eq!(0, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test if the offset is updated properly.
    fn test_offset_tracking() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);

        for i in 0..10 {
            assert_eq!(i, memnode.offset.load(Ordering::Relaxed));
            let buffer: &mut [u8; 1] = &mut [0; 1];
            assert_eq!(memnode.read(buffer.as_ptr() as u64, 1, -1), 1);
            assert_eq!(buffer[0], 0xb);
        }

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 1, -1), 0);
        assert_eq!(buffer[0], 0);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test reading the file at a given offset.
    fn test_read_at_offset() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 1, 9), 1);
        assert_eq!(buffer[0], 0xb);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 1, -1), 0);
        assert_eq!(buffer[0], 0);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test reading the file at a given offset at EOF.
    fn test_read_at_eof_offset() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(memnode.read(buffer.as_ptr() as u64, 1, 10), 0);
        assert_eq!(buffer[0], 0);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test writing the file at the given offset.
    fn test_write_at_offset() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, 0), 10);

        let rbuffer: &mut [u8; 10] = &mut [0; 10];
        assert_eq!(memnode.read(rbuffer.as_ptr() as u64, 10, 0), 10);
        assert_eq!(rbuffer[0], 0xb);
        assert_eq!(rbuffer[9], 0xb);
        assert_eq!(10, memnode.get_file_size());
    }

    #[test]
    /// Test writing the file at the given offset.
    fn test_write_at_eof_offset() {
        let filename = "file.txt";
        let mut memnode = MemNode::new(1, filename, S_IRWXU, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        let rbuffer: &mut [u8; 20] = &mut [0; 20];

        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, -1), 10);
        assert_eq!(memnode.read(rbuffer.as_ptr() as u64, 10, -1), 10);
        assert_eq!(rbuffer[0], 0xb);
        assert_eq!(rbuffer[9], 0xb);

        // This will fill the file between EOF and offset with zeros
        assert_eq!(memnode.write(buffer.as_ptr() as u64, 10, 20), 10);
        assert_eq!(memnode.read(rbuffer.as_ptr() as u64, 20, -1), 20);
        assert_eq!(rbuffer[0], 0);
        assert_eq!(rbuffer[9], 0);
        assert_eq!(rbuffer[10], 0xb);
        assert_eq!(rbuffer[19], 0xb);
        assert_eq!(30, memnode.get_file_size());
    }
}
