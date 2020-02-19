use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use x86::bits64::paging::VAddr;

use crate::arch::process::{UserPtr, UserValue};
use crate::fs::Mnode;

#[derive(Debug)]
pub enum NodeType {
    Directory,
    File,
}

#[derive(Debug)]
pub struct MemNode {
    mnode_num: Mnode,
    name: String,
    node_type: NodeType,
    file: Option<File>,
}

impl MemNode {
    pub fn new(mnode_num: Mnode, pathname: &str, flags: u64, node_type: NodeType) -> MemNode {
        let file = match node_type {
            NodeType::Directory => None,
            NodeType::File => Some(File::new(flags)),
        };

        MemNode {
            mnode_num,
            name: pathname.to_string(),
            node_type,
            file,
        }
    }

    pub fn write(&mut self, buffer: u64, len: u64) -> u64 {
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

    pub fn read(&mut self, buffer: u64, len: u64) -> u64 {
        let mut user_ptr = VAddr::from(buffer);
        let slice_ptr = UserPtr::new(&mut user_ptr);
        let len: usize = len as usize;

        let user_slice = unsafe { core::slice::from_raw_parts_mut(slice_ptr.as_mut_ptr(), len) };
        user_slice.copy_from_slice(self.file.as_ref().unwrap().data.as_slice().split_at(len).0);

        len as u64
    }
}

#[derive(Debug)]
pub struct File {
    data: Vec<u8>,
    flags: u64,
    // TODO: Add more file related attributes
}

impl File {
    pub fn new(flags: u64) -> File {
        File {
            data: Vec::new(),
            flags,
        }
    }
}
