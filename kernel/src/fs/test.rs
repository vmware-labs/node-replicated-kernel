// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Test the file-sytem implementation using unit-tests and proptest.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::{Eq, PartialEq};
use core::sync::atomic::Ordering;

use crate::alloc::borrow::ToOwned;

use kpi::io::*;
use log::trace;
use proptest::prelude::*;

use super::*;
use crate::*;

/// What operations that the model needs to keep track of.
///
/// We don't need to log reads or lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelOperation {
    /// Stores a write to an mnode, at given offset, pattern, length.
    Write(MnodeNum, usize, char, usize),
    /// Stores info about created files.
    Created(String, FileModes, MnodeNum),
}

/// The FS model that we strive to implement.
struct ModelFS {
    /// A log that stores all operations on the model FS.
    oplog: RefCell<Vec<ModelOperation>>,
    /// A counter to hand out mnode identifiers.
    mnode_counter: RefCell<u64>,
}

impl Default for ModelFS {
    fn default() -> Self {
        let oplog = RefCell::new(Vec::with_capacity(64));
        oplog.borrow_mut().push(ModelOperation::Created(
            "/".to_string(),
            FileModes::from_bits_truncate(0),
            1,
        ));
        ModelFS {
            oplog,
            mnode_counter: RefCell::new(1),
        }
    }
}

impl ModelFS {
    /// Find mnode of a path.
    fn path_to_mnode(&self, path: &String) -> Option<MnodeNum> {
        for x in self.oplog.borrow().iter().rev() {
            match x {
                ModelOperation::Created(name, _mode, mnode) => {
                    if &name == &path {
                        return Some(*mnode);
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Find index of a path in the oplog.
    fn path_to_idx(&self, path: &String) -> Option<usize> {
        for (idx, x) in self.oplog.borrow().iter().enumerate().rev() {
            match x {
                ModelOperation::Created(name, _mode, _mnode) => {
                    if &name == &path {
                        return Some(idx);
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Check if a given path exists.
    fn file_exists(&self, path: &String) -> bool {
        self.path_to_mnode(path).is_some()
    }

    /// Check if a mnode exists.
    fn mnode_exists(&self, look_for: MnodeNum) -> bool {
        for x in self.oplog.borrow().iter().rev() {
            match x {
                ModelOperation::Created(_name, _mode, mnode) => {
                    if look_for == *mnode {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// Checks if there is overlap between two ranges
    fn overlaps<T: PartialOrd>(a: &core::ops::Range<T>, b: &core::ops::Range<T>) -> bool {
        a.start < b.end && b.start < a.end
    }

    /// A very silly O(n) method that caculates the intersection between two ranges
    fn intersection(
        a: core::ops::Range<usize>,
        b: core::ops::Range<usize>,
    ) -> Option<core::ops::Range<usize>> {
        if ModelFS::overlaps(&a, &b) {
            let mut min = usize::MAX;
            let mut max = 0;

            for element in a {
                if b.contains(&element) {
                    min = core::cmp::min(element, min);
                    max = core::cmp::max(element, max);
                }
            }
            Some(min..max + 1)
        } else {
            None
        }
    }
}

impl FileSystem for ModelFS {
    // Create just puts the file in the oplop and increases mnode counter.
    fn create(&self, path: String, mode: FileModes) -> Result<u64, KError> {
        if self.file_exists(&path) {
            Err(KError::AlreadyPresent)
        } else {
            *self.mnode_counter.borrow_mut() += 1;
            self.oplog.borrow_mut().push(ModelOperation::Created(
                path,
                mode,
                *self.mnode_counter.borrow(),
            ));
            Ok(*self.mnode_counter.borrow())
        }
    }

    /// Write just logs the write to the oplog.
    ///
    /// Our model assumes that the buffer repeats the first byte for its entire length.
    fn write(&self, mnode_num: MnodeNum, buffer: &[u8], offset: usize) -> Result<usize, KError> {
        if self.mnode_exists(mnode_num) {
            for x in self.oplog.borrow().iter().rev() {
                trace!("seen {:?}", x);
                match x {
                    // Check if the file is writable or not
                    ModelOperation::Created(_path, mode, mnode) => {
                        if mnode_num == *mnode && !FileModes::from(*mode).is_writable() {
                            return Err(KError::PermissionError);
                        }
                    }
                    _ => { /* The operation is not relevant */ }
                }
            }

            if buffer.len() > 0 {
                // Model assumes that buffer is filled with the same pattern all the way
                let pattern: char = buffer[0] as char;
                self.oplog.borrow_mut().push(ModelOperation::Write(
                    mnode_num,
                    offset,
                    pattern,
                    buffer.len(),
                ));
            }
            Ok(buffer.len())
        } else {
            Err(KError::InvalidFile)
        }
    }

    /// read loops through the oplog and tries to fill up the buffer by looking
    /// at the logged `Write` ops.
    ///
    /// This is the hardest operation to represent in the model.
    fn read(
        &self,
        mnode_num: MnodeNum,
        buffer: &mut dyn SliceAccess,
        offset: usize,
    ) -> Result<usize, KError> {
        let _len = buffer.len();
        if self.mnode_exists(mnode_num) {
            // We store our 'retrieved' data in a buffer of Option<u8>
            // to make sure in case we have consecutive writes to the same region
            // we take the last one, and also to detect if we
            // read more than what ever got written to the file...
            let mut buffer_gatherer: Vec<Option<u8>> = Vec::with_capacity(buffer.len());
            for _i in 0..buffer.len() {
                buffer_gatherer.push(None);
            }

            // Start with the latest writes first
            for x in self.oplog.borrow().iter().rev() {
                trace!("seen {:?}", x);
                match x {
                    ModelOperation::Write(fmnode, foffset, fpattern, flength) => {
                        // Write is for the correct file and the offset starts somewhere
                        // in that write
                        let cur_segment_range = *foffset as usize..(*foffset as usize + flength);
                        let read_range = offset as usize..(offset as usize + buffer.len());
                        trace!("*fmnode == mnode_num = {}", *fmnode == mnode_num);
                        trace!(
                            "ModelFS::overlaps(&cur_segment_range, &read_range) = {}",
                            ModelFS::overlaps(&cur_segment_range, &read_range)
                        );
                        if *fmnode == mnode_num
                            && ModelFS::overlaps(&cur_segment_range, &read_range)
                        {
                            let _r = ModelFS::intersection(read_range, cur_segment_range).map(
                                |overlapping_range| {
                                    trace!("overlapping_range = {:?}", overlapping_range);
                                    for idx in overlapping_range {
                                        if buffer_gatherer[idx - offset as usize].is_none() {
                                            // No earlier write, we know that 'pattern' must be at idx
                                            buffer_gatherer[idx - offset as usize] =
                                                Some(*fpattern as u8);
                                        }
                                    }
                                    trace!("buffer_gatherer = {:?}", buffer_gatherer);
                                },
                            );
                        }
                        // else: The write is not relevant
                    }

                    ModelOperation::Created(_path, mode, mnode) => {
                        if mnode_num == *mnode && !FileModes::from(*mode).is_readable() {
                            return Err(KError::PermissionError);
                        }
                    }
                }
            }
            // We need to copy buffer gatherer back in buffer:
            // Something like [1, 2, 3, None] -> Should lead to [1, 2, 3] with Ok(3)
            // Something like [1, None, 3, 4, None] -> Should lead to [1, 0, 3] with Ok(4), I guess?
            let _iter = buffer_gatherer.iter().enumerate().rev();
            let mut drop_top = true;
            let mut bytes_read = 0;
            for (idx, val) in buffer_gatherer.iter().enumerate().rev() {
                if drop_top {
                    if val.is_some() {
                        bytes_read += 1;
                        drop_top = false;
                    } else {
                        // All None's at the end (rev() above) don't count towards
                        // total bytes read since the file wasn't that big
                    }
                } else {
                    bytes_read += 1;
                }
                buffer.write_subslice(&[val.unwrap_or(0)], idx);
            }

            Ok(bytes_read)
        } else {
            Err(KError::InvalidFile)
        }
    }

    /// Lookup just returns the mnode.
    fn lookup(&self, pathname: &str) -> Option<Arc<MnodeNum>> {
        self.path_to_mnode(&String::from(pathname)).map(Arc::from)
    }

    /// Delete finds and removes a path from the oplog again.
    fn delete(&self, pathname: &str) -> Result<(), KError> {
        if let Some(idx) = self.path_to_idx(&String::from(pathname)) {
            self.oplog.borrow_mut().remove(idx);
            // We leave corresponding ModelOperation::Write entries
            // in the log for now...
            Ok(())
        } else {
            Err(KError::InvalidFile)
        }
    }

    /// Returns a `dummy` file-info.
    fn file_info(&self, _mnode: MnodeNum) -> FileInfo {
        FileInfo { ftype: 0, fsize: 0 }
    }

    /// Return a `dummy` response as this function is only used for open with O_TRUNC flag.
    fn truncate(&self, _pathname: &str) -> Result<(), KError> {
        Ok(())
    }

    /// Return a `dummy` response for rename operation
    fn rename(&self, _oldname: &str, _newname: String) -> Result<(), KError> {
        Ok(())
    }

    fn mkdir(&self, _pathname: String, _mode: FileModes) -> Result<(), KError> {
        Ok(())
    }
}

/// Two writes/reads at different offsets should return
/// the correct result.
#[test]
fn model_read() {
    let mfs: ModelFS = Default::default();
    assert!(mfs.create("/bla".into(), FileModes::S_IRWXU.into()).is_ok());
    let mnode = mfs.lookup("/bla").unwrap();

    let wdata1 = &[1, 1];
    assert!(mfs.write(*mnode, wdata1, 0).is_ok());

    let wdata = &[2, 2];
    let r = mfs.write(*mnode, wdata, 4);
    assert_eq!(r, Ok(2));

    let mut rdata = &mut [0, 0];

    let r = mfs.read(*mnode, rdata, 0);
    assert_eq!(rdata, &[1, 1]);
    assert_eq!(r, Ok(2));

    let r = mfs.read(*mnode, rdata, 4);
    assert_eq!(rdata, &[2, 2]);
    assert_eq!(r, Ok(2));
}

/// Two writes that overlap with each other should return
/// the last write.
///
/// Also providing a larger buffer returns 0 in those entries.
#[test]
fn model_overlapping_writes() {
    let mfs: ModelFS = Default::default();
    assert!(mfs.create("/bla".into(), FileModes::S_IRWXU.into()).is_ok());
    let mnode = mfs.lookup("/bla").unwrap();

    let data = &[1, 1, 1];
    assert!(mfs.write(*mnode, data, 0).is_ok());

    let wdata = &[2, 2, 2];
    assert!(mfs.write(*mnode, wdata, 2).is_ok());

    let rdata = &mut [0, 0, 0, 0, 0, 0];
    let r = mfs.read(*mnode, rdata, 0);
    assert_eq!(r, Ok(5));
    assert_eq!(rdata, &[1, 1, 2, 2, 2, 0]);
}

/// Actions that we can perform against the model and the implementation.
///
/// One entry for each function in the FileSystem interface and
/// necessary arguments to construct an operation for said function.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TestAction {
    Read(MnodeNum, usize, usize),
    Write(MnodeNum, usize, char, usize),
    Create(Vec<String>, FileModes),
    Delete(Vec<String>),
    Lookup(Vec<String>),
}

/// Generates one `TestAction` entry randomly.
fn action() -> impl Strategy<Value = TestAction> {
    prop_oneof![
        (mnode_gen(0x1000), offset_gen(0x1000), size_gen(128))
            .prop_map(|(a, b, c)| TestAction::Read(a, b, c)),
        (
            mnode_gen(0x1000),
            offset_gen(0x1000),
            fill_pattern(),
            size_gen(64)
        )
            .prop_map(|(a, b, c, d)| TestAction::Write(a, b, c, d)),
        (path(), mode_gen(0xfff)).prop_map(|(a, b)| TestAction::Create(a, b)),
        path().prop_map(TestAction::Delete),
        path().prop_map(TestAction::Lookup),
    ]
}

/// Generates a vector of TestAction entries (by repeatingly calling `action`).
fn actions() -> impl Strategy<Value = Vec<TestAction>> {
    prop::collection::vec(action(), 0..512)
}

/// Generates one fill pattern (for writes).
fn fill_pattern() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('a'),
        Just('b'),
        Just('c'),
        Just('d'),
        Just('e'),
        Just('f'),
        Just('g'),
        Just('.')
    ]
}

// Generates an offset.
prop_compose! {
    fn offset_gen(max: usize)(offset in 0..max) -> usize { offset }
}

// Generates a random mnode.
prop_compose! {
    fn mnode_gen(max: u64)(mnode in 0..max) -> u64 { mnode }
}

// Generates a random mode.
prop_compose! {
    fn mode_gen(max: u64)(mode in 0..max) -> FileModes { FileModes::from_bits_truncate(mode) }
}

// Generates a random (read/write)-request size.
prop_compose! {
    fn size_gen(max: usize)(size in 0..max) -> usize { size }
}

/// Generates a random path entry.
fn path_names() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::from("/")),
        Just(String::from("nrk")),
        Just(String::from("hello")),
        Just(String::from("world")),
        Just(String::from("memory")),
        Just(String::from("the")),
        Just(String::from("fs")),
        Just(String::from("rusty")),
        Just(String::from("os"))
    ]
}

/// Creates a path of depth a given depth (4), represented as a
/// vector of Strings.
fn path() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(path_names(), 4)
}

proptest! {
    // Verify that our FS implementation behaves according to the `ModelFileSystem`.
    #[test]
    fn model_equivalence(ops in actions()) {
        let model: ModelFS = Default::default();
        let totest: MlnrFS = Default::default();

        use TestAction::*;
        for action in ops {
            match action {
                Read(mnode, offset, len) => {

                    let mut buffer1: Vec<u8> = Vec::with_capacity(len);
                    let mut buffer2: Vec<u8> = Vec::with_capacity(len);

                    let rmodel = model.read(mnode, &mut buffer1.as_mut_slice(), offset);
                    let rtotest = totest.read(mnode, &mut buffer2.as_mut_slice(), offset);
                    assert_eq!(rmodel, rtotest);
                    assert_eq!(buffer1, buffer2);
                }
                Write(mnode, offset, pattern, len) => {
                    let mut buffer: Vec<u8> = Vec::with_capacity(len);
                    for _i in 0..len {
                        buffer.push(pattern as u8);
                    }

                    let rmodel = model.write(mnode, &mut buffer, offset);
                    let rtotest = totest.write(mnode, &mut buffer, offset);
                    assert_eq!(rmodel, rtotest);
                }
                Create(path, mode) => {
                    let path_str = path.join("/");

                    let rmodel = model.create(path_str.clone(), mode);
                    let rtotest = totest.create(path_str, mode);
                    assert_eq!(rmodel, rtotest);
                }
                Delete(path) => {
                    let path_str = path.join("/");

                    let rmodel = model.delete(path_str.as_str());
                    let rtotest = totest.delete(path_str.as_str());
                    assert_eq!(rmodel, rtotest);
                }
                Lookup(path) => {
                    let path_str = path.join("/");

                    let rmodel = model.lookup(path_str.as_str());
                    let rtotest = totest.lookup(path_str.as_str());
                    assert_eq!(rmodel, rtotest);
                }
            }
        }
    }
}

/// Initialize and update file descriptor mnode number and permission flags.
#[test]
fn test_file_descriptor() {
    use crate::fs::fd::FileDescriptorEntry;
    let mut fd = FileDescriptorEntry::default();
    assert_eq!(fd.mnode(), 0x0);
    assert_eq!(fd.flags(), FileFlags::O_NONE);

    fd.update(1, FileFlags::O_RDWR);
    assert_eq!(fd.mnode(), 1);
    assert_eq!(fd.flags(), FileFlags::O_RDWR);
}

/// Initialize memfs for root and verify the values.
#[test]
fn test_memfs_init() {
    let memfs: MlnrFS = Default::default();
    let root = String::from("/");
    assert_eq!(memfs._root, (root.to_owned(), 1));
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 2);
    assert_eq!(memfs.files.read().get(&root), Some(&Arc::new(1)));
    assert_eq!(
        *memfs.mnodes.read().get(&1).unwrap().read(),
        MemNode::new(1, "/", FileModes::S_IRWXU.into(), FileType::Directory).unwrap()
    );
}

#[test]
/// Create a file on in-memory fs and verify all the values.
fn test_file_create() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRUSR.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
}

/// Create a file with non-read permission and try to read it.
#[test]

fn test_file_read_permission_error() {
    let buffer = &mut [0; 10];
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IWUSR.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    // On error read returns 0.
    assert_eq!(memfs.read(2, buffer, 0).is_err(), true);
}

/// Create a file with non-write permission and try to write it.
#[test]
fn test_file_write_permission_error() {
    let buffer = &[0; 10];
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRUSR.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    // On error read returns 0.
    assert_eq!(memfs.write(2, buffer, 0), Err(KError::PermissionError));
}

/// Create a file and write to it.
#[test]
fn test_file_write() {
    let buffer = &[0; 10];
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(memfs.write(2, buffer, 0).unwrap(), 10);
}

/// Create a file, write to it and then later read. Verify the content.
#[test]
fn test_file_read() {
    let len = 10;
    let wbuffer: &[u8; 10] = &[0xb; 10];
    let rbuffer: &mut [u8; 10] = &mut [0; 10];

    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(memfs.write(2, wbuffer, 0).unwrap(), len);
    assert_eq!(memfs.read(2, rbuffer, 0).unwrap(), len);
    assert_eq!(rbuffer[0], 0xb);
    assert_eq!(rbuffer[9], 0xb);
}

/// Create a file and lookup for it.
#[test]
fn test_file_lookup() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    let mnode = memfs.lookup(filename);
    assert_eq!(mnode, Some(Arc::new(2)));
}

/// Lookup for a fake file.
#[test]
fn test_file_fake_lookup() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    let mnode = memfs.lookup("filename");
    assert_eq!(mnode, None);
}

/// Try to create a file with same name.
#[test]
fn test_file_duplicate_create() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(
        memfs.create(filename.into(), FileModes::S_IRWXU.into()),
        Err(KError::AlreadyPresent)
    );
}

/// Test file_info.
#[test]
fn test_file_info() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.read().get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(memfs.file_info(2), FileInfo { ftype: 2, fsize: 0 });
}

/// Test file deletion.
#[test]
fn test_file_delete() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let buffer: &mut [u8; 10] = &mut [0xb; 10];

    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.delete(filename), Ok(()));
    assert_eq!(memfs.delete(filename).is_err(), true);
    assert_eq!(memfs.lookup(filename), None);
    assert_eq!(memfs.write(2, buffer, 0), Err(KError::InvalidFile));
    assert_eq!(memfs.read(2, buffer, 0), Err(KError::InvalidFile));
}

#[test]
fn test_file_rename() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let newname = "filenew.txt";
    let oldmnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert!(memfs.rename(filename, newname.into()).is_ok());
    let mnode = memfs.lookup(newname).unwrap();
    assert_eq!(oldmnode, *mnode);
}

#[test]
fn test_file_rename_and_read() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let newname = "filenew.txt";
    let mnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();

    let buffer: &mut [u8; 10] = &mut [0xb; 10];
    assert_eq!(memfs.write(mnode, buffer, 0), Ok(10));

    let rbuffer: &mut [u8; 10] = &mut [0x0; 10];
    assert!(memfs.rename(filename, newname.into()).is_ok());
    let mnode = memfs.lookup(newname).unwrap();
    assert_eq!(memfs.read(*mnode, rbuffer, 0), Ok(10));
    assert_eq!(rbuffer[0], 0xb);
    assert_eq!(rbuffer[9], 0xb);
}

#[test]
fn test_file_rename_and_write() {
    let memfs: MlnrFS = Default::default();
    let filename = "file.txt";
    let newname = "filenew.txt";
    let oldmnode = memfs
        .create(filename.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert!(memfs.rename(filename, newname.into()).is_ok());
    let mnode = memfs.lookup(newname).unwrap();
    assert_eq!(oldmnode, *mnode);

    let finfo = memfs.file_info(*mnode);
    assert_eq!(finfo.fsize, 0);
    let buffer: &mut [u8; 10] = &mut [0xb; 10];
    assert_eq!(memfs.write(*mnode, buffer, 0), Ok(10));
    let finfo = memfs.file_info(*mnode);
    assert_eq!(finfo.fsize, 10);
}

#[test]
fn test_file_rename_nonexistent_file() {
    let memfs: MlnrFS = Default::default();
    let oldname = "file.txt";
    let newname = "filenew.txt";
    assert_eq!(
        memfs.rename(oldname, newname.into()),
        Err(KError::InvalidFile)
    );
}

#[test]
fn test_file_rename_to_existent_file() {
    let memfs: MlnrFS = Default::default();
    let oldname = "file.txt";
    let newname = "filenew.txt";
    let oldmnode = memfs
        .create(oldname.into(), FileModes::S_IRWXU.into())
        .unwrap();
    let newmnode = memfs
        .create(newname.into(), FileModes::S_IRWXU.into())
        .unwrap();
    assert_ne!(oldmnode, newmnode);
    assert_eq!(memfs.rename(oldname, newname.into()), Ok(()));

    // Old file is removed.
    assert_eq!(memfs.lookup(oldname), None);
    // New file points to old mnode.
    assert_eq!(*memfs.lookup(newname).unwrap(), oldmnode);
}
