use alloc::string::String;
use alloc::string::ToString;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::process::UserSlice;
use crate::fs::file::*;
use crate::fs::{FileSystemError, Mnode, Modes};

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
    pub fn new(
        mnode_num: Mnode,
        pathname: &str,
        modes: Modes,
        node_type: NodeType,
    ) -> Result<MemNode, FileSystemError> {
        let file = match node_type {
            NodeType::Directory => None,
            NodeType::File => match File::new(modes) {
                Ok(file) => Some(file),
                Err(e) => return Err(e),
            },
        };

        Ok(MemNode {
            mnode_num,
            name: pathname.to_string(),
            node_type,
            file,
            offset: AtomicUsize::new(0),
        })
    }

    /// Write to an in-memory file.
    pub fn write(&mut self, mut buffer: &mut [u8], offset: i64) -> Result<usize, FileSystemError> {
        // Return if the user doesn't have write permissions for the file.
        if self.node_type != NodeType::File || !self.file.as_ref().unwrap().get_mode().is_writable()
        {
            return Err(FileSystemError::PermissionError);
        }
        let len: usize = buffer.len();

        self.file
            .as_mut()
            .unwrap()
            .write_file(&mut buffer, len, offset)
    }

    /// Read from an in-memory file.
    pub fn read(&self, buffer: &mut UserSlice, offset: i64) -> Result<usize, FileSystemError> {
        // Return if the user doesn't have read permissions for the file.
        if self.node_type != NodeType::File || !self.file.as_ref().unwrap().get_mode().is_readable()
        {
            return Err(FileSystemError::PermissionError);
        }

        let len: usize = buffer.len();
        let file_size = self.get_file_size();

        let mut old_offset;
        let mut new_offset;
        let mut file_offset;
        loop {
            old_offset = self.offset.load(Ordering::Acquire);
            file_offset = old_offset;

            // If offset is specified and its less than the file size,
            // then update the current offset.
            if offset != -1 {
                if offset as usize <= file_size {
                    file_offset = offset as usize;
                } else {
                    return Err(FileSystemError::InvalidOffset);
                }
            }
            let bytes_to_read = core::cmp::min(file_size - file_offset, len);
            new_offset = file_offset + bytes_to_read;

            // Return error if start-offset is greater than or equal to new-offset OR
            // new offset is greater than the file size.
            if file_offset >= new_offset || new_offset > self.get_file_size() as usize {
                return Err(FileSystemError::InvalidOffset);
            }

            // Try updating the offset.
            match self.update_offset(old_offset, new_offset) {
                true => break,
                false => continue,
            }
        }

        // Read from file only if its not at EOF.
        match self
            .file
            .as_ref()
            .unwrap()
            .read_file(&mut *buffer, file_offset, new_offset)
        {
            Ok(len) => return Ok(len),
            Err(e) => return Err(e),
        }
    }

    /// Update the offset after reading the file.
    ///
    /// This is function is called after handling all the error conditions.
    fn update_offset(&self, old_offset: usize, new_offset: usize) -> bool {
        if self
            .offset
            .compare_and_swap(old_offset, new_offset, Ordering::Release)
            == old_offset
        {
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
    use kpi::io::*;

    #[test]
    /// Create mnode directory and verify the values.
    fn test_mnode_directory() {
        let filename = "dir";
        let memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::Directory).unwrap();
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::Directory);
    }

    #[test]
    /// Create mnode file and verify the values.
    fn test_mnode_file() {
        let filename = "file.txt";
        let memnode = MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
    }

    #[test]
    fn test_mnode_write_directory() {
        let filename = "dir";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::Directory).unwrap();
        assert_eq!(memnode.file, None);
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::Directory);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode.write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
            Err(FileSystemError::PermissionError)
        );
    }

    #[test]
    /// Write to mnode file and verify the values.
    fn test_mnode_file_write() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );
    }

    #[test]
    /// Write to mnode file which doesn't have write permissions.
    fn test_mnode_file_write_permission_error() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRUSR.into(), NodeType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRUSR.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode.write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
            Err(FileSystemError::PermissionError)
        );
    }

    #[test]
    /// Read from mnode file.
    fn test_mnode_file_read() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IRWXU.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );
        let buffer: &mut [u8; 10] = &mut [0; 10];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
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
        let memnode = MemNode::new(1, filename, FileModes::S_IWUSR.into(), NodeType::File).unwrap();
        assert_eq!(
            memnode.file,
            Some(File::new(FileModes::S_IWUSR.into()).unwrap())
        );
        assert_eq!(memnode.mnode_num, 1);
        assert_eq!(memnode.name, filename.to_string());
        assert_eq!(memnode.node_type, NodeType::File);
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode.read(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
            Err(FileSystemError::PermissionError)
        );
    }

    #[test]
    /// Test update offset method
    fn test_update_offset() {
        let filename = "file.txt";
        let memnode = MemNode::new(1, filename, FileModes::S_IWUSR.into(), NodeType::File).unwrap();
        assert_eq!(false, memnode.update_offset(1, 10));
        assert_eq!(true, memnode.update_offset(0, 0));
        assert_eq!(0, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test if the offset is updated properly.
    fn test_offset_tracking() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );

        for i in 0..10 {
            assert_eq!(i, memnode.offset.load(Ordering::Relaxed));
            let buffer: &mut [u8; 1] = &mut [0; 1];
            assert_eq!(
                memnode
                    .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), -1)
                    .unwrap(),
                1
            );
            assert_eq!(buffer[0], 0xb);
        }

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), -1)
                .is_err(),
            true
        );
        assert_eq!(buffer[0], 0);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test reading the file at a given offset.
    fn test_read_at_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 9)
                .unwrap(),
            1
        );
        assert_eq!(buffer[0], 0xb);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), -1)
                .is_err(),
            true
        );
        assert_eq!(buffer[0], 0);
        assert_eq!(10, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test reading the file at a given offset at EOF.
    fn test_read_at_eof_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );

        let buffer: &mut [u8; 1] = &mut [0; 1];
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(buffer.as_ptr() as u64, 1), 10)
                .is_err(),
            true
        );
        assert_eq!(buffer[0], 0);
        assert_eq!(0, memnode.offset.load(Ordering::Relaxed));
    }

    #[test]
    /// Test writing the file at the given offset.
    fn test_write_at_offset() {
        let filename = "file.txt";
        let mut memnode =
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        let buffer: &[u8; 10] = &[0xb; 10];
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), 0)
                .unwrap(),
            10
        );

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
            MemNode::new(1, filename, FileModes::S_IRWXU.into(), NodeType::File).unwrap();
        let buffer: &[u8; 10] = &[0xb; 10];
        let rbuffer: &mut [u8; 20] = &mut [0; 20];

        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(rbuffer.as_ptr() as u64, 10), -1)
                .unwrap(),
            10
        );
        assert_eq!(rbuffer[0], 0xb);
        assert_eq!(rbuffer[9], 0xb);

        // This will fill the file between EOF and offset with zeros
        assert_eq!(
            memnode
                .write(&mut UserSlice::new(buffer.as_ptr() as u64, 10), 20)
                .unwrap(),
            10
        );
        assert_eq!(
            memnode
                .read(&mut UserSlice::new(rbuffer.as_ptr() as u64, 20), -1)
                .unwrap(),
            20
        );
        assert_eq!(rbuffer[0], 0);
        assert_eq!(rbuffer[9], 0);
        assert_eq!(rbuffer[10], 0xb);
        assert_eq!(rbuffer[19], 0xb);
        assert_eq!(30, memnode.get_file_size());
    }
}
