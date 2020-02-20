use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use kpi::io::*;
use x86::bits64::paging::VAddr;

use crate::arch::process::{UserPtr, UserValue};
use crate::fs::{Mnode, Modes};

/// Each memory-node can be of two types: directory or a file.
#[derive(Debug)]
pub enum NodeType {
    Directory,
    File,
}

/// Memnode representation, similar to Inode for a memory-fs.
#[derive(Debug)]
pub struct MemNode {
    mnode_num: Mnode,
    name: String,
    node_type: NodeType,
    file: Option<File>,
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
        }
    }

    /// Write to an in-memory file.
    pub fn write(&mut self, buffer: u64, len: u64) -> u64 {
        let modes = self.file.as_ref().unwrap().modes;
        // Return if the user doesn't have write permissions for the file.
        if !is_allowed!(modes, S_IWUSR) {
            return 0;
        }
        let buffer: *const u8 = buffer as *const u8;
        let len: usize = len as usize;

        let user_slice = unsafe { &mut core::slice::from_raw_parts(buffer, len) };
        let userval = UserValue::new(user_slice);
        self.file
            .as_mut()
            .unwrap()
            .data
            .append(&mut userval.to_vec());

        len as u64
    }

    /// Read from an in-memory file.
    pub fn read(&mut self, buffer: u64, len: u64) -> u64 {
        let modes = self.file.as_ref().unwrap().modes;
        // Return if the user doesn't have read permissions for the file.
        if !is_allowed!(modes, S_IRUSR) {
            return 0;
        }
        let mut user_ptr = VAddr::from(buffer);
        let slice_ptr = UserPtr::new(&mut user_ptr);
        let len: usize = len as usize;

        let user_slice = unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
        user_slice.copy_from_slice(self.file.as_ref().unwrap().data.as_slice().split_at(len).0);

        len as u64
    }
}

/// An in-memory file, which is just a vector and stores permissions.
#[derive(Debug)]
pub struct File {
    data: Vec<u8>,
    modes: Modes,
    // TODO: Add more file related attributes
}

impl File {
    pub fn new(modes: Modes) -> File {
        File {
            data: Vec::new(),
            modes,
        }
    }
}
