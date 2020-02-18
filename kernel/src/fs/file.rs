use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::fs::Mnode;

#[derive(Debug)]
pub enum NodeType {
    Directory,
    File,
}

#[derive(Debug)]
pub struct MemNode {
    mnode_num: Mnode,
    file: File,
    node_type: NodeType,
}

impl MemNode {
    pub fn new(mnode_num: Mnode, pathname: &str, flags: u64, node_type: NodeType) -> MemNode {
        MemNode {
            mnode_num,
            file: File::new(pathname, flags),
            node_type,
        }
    }
}

#[derive(Debug)]
pub struct File {
    filename: String,
    data: Vec<u8>,
    flags: u64,
    // TODO: Add more file related attributes
}

impl File {
    pub fn new(filename: &str, flags: u64) -> File {
        File {
            filename: filename.to_string(),
            data: Vec::new(),
            flags,
        }
    }
}
