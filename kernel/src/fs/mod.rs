//! The core module for file management.
//!

mod file;
mod name;

use alloc::string::String;
use alloc::string::ToString;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;

use crate::fs::file::{MemNode, NodeType};

pub const MAX_FILES_PER_PROCESS: usize = 8;

type Mnode = u64;
type Flags = u64;
type Modes = u64;

pub trait FileDescriptor {
    fn init_fd() -> Fd;
    fn update_fd(&mut self, mnode: Mnode, flags: Flags);
}

#[derive(Debug, Default)]
pub struct Fd {
    mnode: Mnode,
    flags: Flags,
}

impl FileDescriptor for Fd {
    fn init_fd() -> Fd {
        Fd { mnode: 1, flags: 2 }
    }

    fn update_fd(&mut self, mnode: Mnode, flags: Flags) {
        self.mnode = mnode;
        self.flags = flags;
    }
}

#[derive(Debug)]
pub struct MemFS {
    mnodes: HashMap<Mnode, MemNode>,
    files: HashMap<String, Mnode>,
    root: (String, Mnode),
    nextmemnode: AtomicUsize,
}

impl MemFS {
    pub fn init() -> MemFS {
        let rootdir = "/";
        let rootmnode = 1;

        let mut mnodes = HashMap::new();
        mnodes.insert(
            rootmnode,
            MemNode::new(rootmnode, rootdir, 0, NodeType::Directory),
        );
        let mut files = HashMap::new();
        files.insert(rootdir.to_string(), 1);
        let root = (rootdir.to_string(), 1);

        MemFS {
            mnodes,
            files,
            root,
            nextmemnode: AtomicUsize::new(2),
        }
    }

    fn get_next_ino(&mut self) -> usize {
        self.nextmemnode.fetch_add(1, Ordering::Relaxed)
    }

    pub fn creat(&mut self, pathname: u64, modes: Modes) -> u64 {
        let filename = "abc";

        let mnode_num = self.get_next_ino() as u64;
        let memnode = MemNode::new(mnode_num, filename, modes, NodeType::File);
        self.files.insert(filename.to_string(), mnode_num);
        self.mnodes.insert(mnode_num, memnode);

        mnode_num
    }
}
