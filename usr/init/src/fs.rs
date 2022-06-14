// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Test file-system syscall implementation using unit-tests.
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::{max, min, Eq, PartialEq};
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;

use vibrio::io::*;
use vibrio::SystemCallError;

use log::trace;
use proptest::prelude::*;

pub type Mnode = u64;

const MAX_FILES_PER_PROCESS: usize = 4096;

/// What operations that the model needs to keep track of.
///
/// We don't need to log reads or lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelOperation {
    /// Stores a write to an mnode, at given offset, pattern, length.
    Write(Mnode, i64, char, u64),
    /// Stores info about created files.
    Created(String, FileModes, Mnode),
}

/// A file descriptor representaion.
#[derive(Debug, Default)]
pub struct Fd {
    mnode: Mnode,
    flags: FileFlags,
    offset: AtomicUsize,
}

impl Fd {
    fn update_fd(&mut self, mnode: Mnode, flags: FileFlags) {
        self.mnode = mnode;
        self.flags = flags;
    }

    fn get_mnode(&self) -> Mnode {
        self.mnode
    }

    fn get_flags(&self) -> FileFlags {
        self.flags
    }

    fn get_offset(&self) -> usize {
        self.offset.load(Ordering::Relaxed)
    }

    fn update_offset(&self, new_offset: usize) {
        self.offset.store(new_offset, Ordering::Release);
    }
}

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
    pub fn allocate_fd(&mut self) -> Result<(u64, &mut Fd), SystemCallError> {
        if let Some(fid) = self.fds.iter().position(|fd| fd.is_none()) {
            self.fds[fid] = Some(Default::default());
            Ok((fid as u64, self.fds[fid as usize].as_mut().unwrap()))
        } else {
            trace!("allocate_fd: Failed to allocate file descriptor");
            Err(SystemCallError::InternalError)
        }
    }

    pub fn deallocate_fd(&mut self, fd: u64) -> Result<u64, SystemCallError> {
        match self.fds.get_mut(fd as usize) {
            Some(fdinfo) => match fdinfo {
                Some(info) => {
                    trace!("deallocate_fd: removing {:?}", info);
                    *fdinfo = None;
                    Ok(fd)
                }
                None => {
                    trace!(
                        "deallocate_fd: Found fd at index {:?} but value wasn't actually set.",
                        fd
                    );
                    Err(SystemCallError::InternalError)
                }
            },
            None => Err(SystemCallError::InternalError),
        }
    }

    pub fn get_fd(&self, index: usize) -> Result<&Fd, SystemCallError> {
        if let Some(fd) = self.fds[index].as_ref() {
            Ok(fd)
        } else {
            trace!("get_fd: Failed to find fd at index {:?}", index);
            Err(SystemCallError::InternalError)
        }
    }
}

/// The FS model that we strive to implement.
struct ModelFIO {
    /// A log that stores all operations on the model FS.
    oplog: RefCell<Vec<ModelOperation>>,
    /// A counter to hand out mnode identifiers.
    mnode_counter: RefCell<u64>,
    /// File descriptors
    fds: FileDesc,
}

impl Default for ModelFIO {
    fn default() -> Self {
        let oplog = RefCell::new(Vec::with_capacity(64));
        oplog
            .borrow_mut()
            .push(ModelOperation::Created("/".to_string(), 0.into(), 1));
        ModelFIO {
            oplog,
            mnode_counter: RefCell::new(1),
            fds: Default::default(),
        }
    }
}

impl ModelFIO {
    /// Find mnode of a path.
    fn path_to_mnode(&self, path: &String) -> Option<Mnode> {
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

    /// Check if a mnode exists.
    fn mnode_exists(&self, look_for: Mnode) -> bool {
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

    fn file_size(&self, look_for: Mnode) -> i64 {
        let mut len = 0;
        for x in self.oplog.borrow().iter().rev() {
            match x {
                ModelOperation::Write(mnode, foffset, _fpattern, flength) => {
                    if look_for == *mnode {
                        len = max(foffset + *flength as i64, len);
                    }
                }
                // Disregard any operations before file creation
                ModelOperation::Created(_, _, mnode) => {
                    if look_for == *mnode {
                        return len;
                    }
                }
            }
        }
        len
    }

    fn remove_entries(&self, look_for: Mnode, remove_created: bool, remove_write: bool) {
        let mut my_idxs = Vec::new();
        for (idx, x) in self.oplog.borrow().iter().enumerate().rev() {
            match x {
                ModelOperation::Write(current_mnode, _foffset, _fpattern, _flength) => {
                    if remove_write && &look_for == current_mnode {
                        my_idxs.push(idx);
                    }
                }
                ModelOperation::Created(_path, _modes, current_mnode) => {
                    if remove_created && &look_for == current_mnode {
                        my_idxs.push(idx);
                    }
                }
            }
        }

        let mut oplog = self.oplog.borrow_mut();
        for idx in my_idxs.iter() {
            let _removed = oplog.remove(*idx);
        }
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
        if ModelFIO::overlaps(&a, &b) {
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

    // Create just puts the file in the oplop and increases mnode counter.
    pub fn open<T: AsRef<str>>(
        &mut self,
        path: T,
        flags: FileFlags,
        modes: FileModes,
    ) -> Result<u64, SystemCallError> {
        let path_str = path.as_ref().to_string();
        let flags = FileFlags::from(flags);
        let mut modes = FileModes::from(modes);

        if flags.is_append() && flags.is_truncate() {
            trace!("open() - both truncate and append flags were set");
            return Err(SystemCallError::InternalError);
        }

        // If file exists, only create new fd
        if let Some(mnode) = self.lookup(path.as_ref()) {
            if flags.is_create() {
                trace!("open() - create flag specified for file that already exists");
                //Err(SystemCallError::InternalError)
            }

            let size = self.file_size(mnode);
            let idx = self.path_to_idx(&path_str).unwrap();
            if let ModelOperation::Created(_path, old_modes, _mnode) =
                self.oplog.borrow().get(idx).unwrap()
            {
                modes = *old_modes;
            }
            let (fid, fd) = self.fds.allocate_fd()?;
            fd.update_fd(mnode, flags);

            if flags.is_append() {
                fd.update_offset(size as usize);
            } else if flags.is_truncate() {
                if modes.is_writable() {
                    self.remove_entries(mnode, false, true);
                } else {
                    trace!("open() - no write permissions, so cannot truncate");
                    self.fds.deallocate_fd(fid)?;
                    return Err(SystemCallError::InternalError);
                }
            }

            Ok(fid)

        // Create new file if necessary
        } else {
            if !flags.is_create() {
                trace!("open() - called on non-existing file without create flag");
                return Err(SystemCallError::InternalError);
            }

            *self.mnode_counter.borrow_mut() += 1;
            let mnode = *self.mnode_counter.borrow();
            self.oplog.borrow_mut().push(ModelOperation::Created(
                path_str,
                FileModes::from(modes),
                mnode,
            ));
            let (fid, fd) = self.fds.allocate_fd()?;
            fd.update_fd(mnode, flags);
            Ok(fid)
        }
    }

    pub fn write(&self, fid: u64, buffer: &[u8]) -> Result<u64, SystemCallError> {
        self.write_at(fid, buffer, -1)
    }

    /// Write just logs the write to the oplog.
    ///
    /// Our model assumes that the buffer repeats the first byte for its entire length.
    pub fn write_at(&self, fid: u64, buffer: &[u8], offset: i64) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong... should be InternalError??
        if buffer.len() == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let fd = self.fds.get_fd(fid as usize)?;
        let flags = fd.get_flags();

        // check for write permissions
        if !flags.is_write() {
            trace!("write_at() - File {:?} lacks write flag permissions", fid);
            return Err(SystemCallError::InternalError);
        }

        let mnode = fd.get_mnode();
        if self.mnode_exists(mnode) {
            let mut my_offset = offset;
            if my_offset == -1 {
                if fd.get_flags().is_append() {
                    my_offset = self.file_size(mnode);
                } else {
                    my_offset = fd.get_offset() as i64;
                }
            }

            for x in self.oplog.borrow().iter().rev() {
                match x {
                    // Check if the file is writable or not
                    ModelOperation::Created(_path, mode, current_mnode) => {
                        if mnode == *current_mnode && !mode.is_writable() {
                            trace!(
                                "write_at() - File {:?} lacks write mode permissions {:?}",
                                fid,
                                mode
                            );
                            return Err(SystemCallError::InternalError);
                        }
                    }
                    _ => { /* The operation is not relevant */ }
                }
            }

            if buffer.len() > 0 {
                // Model assumes that buffer is filled with the same pattern all the way
                let pattern = buffer[0] as char;
                self.oplog.borrow_mut().push(ModelOperation::Write(
                    mnode,
                    my_offset,
                    pattern,
                    buffer.len() as u64,
                ));

                if offset == -1 {
                    fd.update_offset(my_offset as usize + buffer.len());
                }
            }

            Ok(buffer.len() as u64)
        } else {
            trace!("write_at() - Failed to find mnode for fid {:?}", fid);
            Err(SystemCallError::InternalError)
        }
    }

    pub fn read(&self, fid: u64, buffer: &mut [u8]) -> Result<u64, SystemCallError> {
        self.read_at(fid, buffer, -1)
    }

    /// read loops through the oplog and tries to fill up the buffer by looking
    /// at the logged `Write` ops.
    ///
    /// This is the hardest operation to represent in the model.
    pub fn read_at(
        &self,
        fid: u64,
        buffer: &mut [u8],
        offset: i64,
    ) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong, should be internal Error??
        if buffer.len() == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let fd = self.fds.get_fd(fid as usize)?;
        let mut my_offset = offset;
        if my_offset == -1 {
            my_offset = fd.get_offset() as i64;
        }

        let flags = fd.get_flags();

        // check for read permissions
        if !flags.is_read() {
            trace!("read_at() - File {:?} lacks read flag permissions", fid);
            return Err(SystemCallError::InternalError);
        }

        let mnode = fd.get_mnode();
        if self.mnode_exists(mnode) {
            for x in self.oplog.borrow().iter().rev() {
                match x {
                    ModelOperation::Created(_path, mode, cmnode) => {
                        if mnode == *cmnode && !mode.is_readable() {
                            trace!(
                                "read_at() - File {:?} lacks read mode permissions {:?}",
                                fid,
                                mode
                            );
                            return Err(SystemCallError::InternalError);
                        }
                    }
                    _ => {}
                }
            }

            // If offset is beyond file size, nothing to read
            let size = self.file_size(mnode);
            if my_offset >= size {
                return Ok(0);
            }

            // Calculate how many bytes we expect to read
            let expected_bytes = min(size - my_offset, buffer.len() as i64);
            if expected_bytes == 0 {
                return Ok(0);
            }

            // We store our 'retrieved' data in a buffer of Option<u8>
            // to make sure in case we have consecutive writes to the same region
            // we take the last one, and also to detect if we
            // read more than what ever got written to the file...
            let mut buffer_gatherer: Vec<Option<u8>> = Vec::with_capacity(expected_bytes as usize);
            for _i in 0..expected_bytes {
                buffer_gatherer.push(None);
            }

            // Start with the latest writes first
            for x in self.oplog.borrow().iter().rev() {
                match x {
                    ModelOperation::Write(wmnode, foffset, fpattern, flength) => {
                        // Write is for the correct file and the offset starts somewhere
                        // in that write
                        let cur_segment_range =
                            *foffset as usize..(*foffset as usize + *flength as usize);
                        let read_range =
                            my_offset as usize..(my_offset as usize + expected_bytes as usize);
                        trace!("*wfd == fd = {}", *wmnode == mnode);
                        trace!(
                            "ModelFIO::overlaps(&cur_segment_range, &read_range) = {}",
                            ModelFIO::overlaps(&cur_segment_range, &read_range)
                        );
                        if *wmnode == mnode && ModelFIO::overlaps(&cur_segment_range, &read_range) {
                            let _r = ModelFIO::intersection(read_range, cur_segment_range).map(
                                |overlapping_range| {
                                    trace!("overlapping_range = {:?}", overlapping_range);
                                    for idx in overlapping_range {
                                        if buffer_gatherer[idx - my_offset as usize].is_none() {
                                            // No earlier write, we know that 'pattern' must be at idx
                                            buffer_gatherer[idx - my_offset as usize] =
                                                Some(*fpattern as u8);
                                        }
                                    }
                                    trace!("buffer_gatherer = {:?}", buffer_gatherer);
                                },
                            );
                        }
                        // else: The write is not relevant
                    }
                    _ => {}
                }
            }
            // We need to copy buffer gatherer back in buffer:
            // Something like [1, 2, 3, None] -> Should lead to [1, 2, 3] with Ok(3)
            // Something like [1, None, 3, 4, None] -> Should lead to [1, 0, 3] with Ok(4), I guess?
            let _iter = buffer_gatherer.iter().enumerate().rev();
            let mut drop_top = true;
            let mut _bytes_read = 0;
            for (idx, val) in buffer_gatherer.iter().enumerate().rev() {
                if drop_top {
                    if val.is_some() {
                        _bytes_read += 1;
                        drop_top = false;
                    } else {
                        // All None's at the end (rev() above) don't count towards
                        // total bytes read since the file wasn't that big
                    }
                } else {
                    _bytes_read += 1;
                }

                buffer[idx] = val.unwrap_or(0);
                trace!("buffer = {:?}", buffer);
            }

            if offset == -1 {
                fd.update_offset(my_offset as usize + expected_bytes as usize);
            }
            Ok(expected_bytes as u64)
        } else {
            trace!("read_at() - Failed to find mnode for fid {:?}", fid);
            Err(SystemCallError::InternalError)
        }
    }

    /// Lookup just returns the mnode.
    fn lookup(&self, pathname: &str) -> Option<Mnode> {
        self.path_to_mnode(&String::from(pathname))
    }

    /// Delete finds and removes a path from the oplog again.
    pub fn delete(&self, path: &str) -> Result<(), SystemCallError> {
        // TODO: Check to see if there are any open fds to this mnode.
        if let Some(mnode) = self.lookup(path) {
            self.remove_entries(mnode, true, true);
            Ok(())
        } else {
            trace!("delete() - Failed to find mnode for path {:?}", path);
            Err(SystemCallError::InternalError)
        }
    }

    pub fn close(&mut self, fid: u64) -> Result<(), SystemCallError> {
        self.fds.deallocate_fd(fid)?;
        Ok(())
    }
}

/// Actions that we can perform against the model and the implementation.
///
/// One entry for each function in the FileSystem interface and
/// necessary arguments to construct an operation for said function.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TestAction {
    Read(u64, usize),
    Write(u64, char, usize),
    ReadAt(u64, usize, i64),
    WriteAt(u64, char, usize, i64),
    Open(Vec<String>, FileFlags, FileModes),
    Delete(Vec<String>),
    Close(u64),
}

/// Generates one `TestAction` entry randomly.
fn action() -> impl Strategy<Value = TestAction> {
    prop_oneof![
        (fd_gen(0xA), size_gen(128)).prop_map(|(a, c)| TestAction::Read(a, c)),
        (fd_gen(0xA), fill_pattern(), size_gen(64))
            .prop_map(|(a, c, d)| TestAction::Write(a, c, d)),
        (fd_gen(0xA), size_gen(128), offset_gen(128))
            .prop_map(|(a, b, c)| TestAction::ReadAt(a, b, c)),
        (fd_gen(0xA), fill_pattern(), size_gen(64), offset_gen(128),)
            .prop_map(|(a, b, c, d)| TestAction::WriteAt(a, b, c, d)),
        (path(), flag_gen(0xfff), mode_gen(0xfff)).prop_map(|(a, b, c)| TestAction::Open(
            a,
            FileFlags::from(b),
            FileModes::from(c)
        )),
        path().prop_map(TestAction::Delete),
        fd_gen(0xA).prop_map(TestAction::Close),
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
    fn offset_gen(max: i64)(offset in 0..max) -> i64 { offset }
}

// Generates a random file descriptor.
const FD_OFFSET: u64 = 100;
prop_compose! {
    fn fd_gen(max: u64)(mnode in 0..max) -> u64 { mnode }
}

// Generates a random mode.
prop_compose! {
    fn mode_gen(max: u64)(mode in 0..max) -> u64 { mode }
}

// Generates a random file flag.
prop_compose! {
    fn flag_gen(max: u64)(flag in 0..max) -> u64 { flag }
}

// Generates a random (read/write)-request size.
prop_compose! {
    fn size_gen(max: usize)(size in 0..max) -> usize { size }
}

/// Generates a random path entry.
fn path_names() -> impl Strategy<Value = String> {
    prop_oneof![
        //Just(String::from("/")),
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

// Verify that our FS implementation behaves according to the `ModelFileSystem`.
fn model_equivalence(ops: Vec<TestAction>) {
    let mut model: ModelFIO = Default::default();
    let mut fd_map: HashMap<u64, u64> = HashMap::new();

    use TestAction::*;
    for action in ops {
        match action {
            Read(fd, len) => {
                let mut rtotest_fd = fd + FD_OFFSET;
                if fd_map.contains_key(&fd) {
                    rtotest_fd = *fd_map.get(&fd).unwrap();
                }

                let mut buffer1 = [0u8; 128];
                let mut buffer2 = [0u8; 128];
                let rmodel = model.read(fd, &mut buffer1[..len]);
                let rtotest = vibrio::syscalls::Fs::read(rtotest_fd, &mut buffer2[..len as usize]);
                assert_eq!(rmodel, rtotest);
                assert_eq!(buffer1, buffer2);
            }
            Write(fd, pattern, len) => {
                let mut rtotest_fd = fd + FD_OFFSET;
                if fd_map.contains_key(&fd) {
                    rtotest_fd = *fd_map.get(&fd).unwrap();
                }

                let mut buffer: Vec<u8> = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    buffer.push(pattern as u8);
                }
                let rmodel = model.write(fd, &buffer[..len]);
                let rtotest = vibrio::syscalls::Fs::write(rtotest_fd, &buffer[..len]);
                assert_eq!(rmodel, rtotest);
            }
            ReadAt(fd, len, offset) => {
                let mut rtotest_fd = fd + FD_OFFSET;
                if fd_map.contains_key(&fd) {
                    rtotest_fd = *fd_map.get(&fd).unwrap();
                }

                let mut buffer1 = [0u8; 128];
                let mut buffer2 = [0u8; 128];
                let rmodel = model.read_at(fd, &mut buffer1[..len], offset);
                let rtotest =
                    vibrio::syscalls::Fs::read_at(rtotest_fd, &mut buffer2[..len], offset);
                assert_eq!(rmodel, rtotest);
                assert_eq!(buffer1, buffer2);
            }
            WriteAt(fd, pattern, len, offset) => {
                let mut rtotest_fd = fd + FD_OFFSET;
                if fd_map.contains_key(&fd) {
                    rtotest_fd = *fd_map.get(&fd).unwrap();
                }

                let mut buffer: Vec<u8> = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    buffer.push(pattern as u8);
                }
                let rmodel = model.write_at(fd, &buffer[..len], offset);
                let rtotest = vibrio::syscalls::Fs::write_at(rtotest_fd, &buffer[..len], offset);
                assert_eq!(rmodel, rtotest);
            }
            Open(path, flags, mode) => {
                let path_str = path.join("/");
                let rmodel = model.open(path_str.clone(), flags, mode);
                let rtotest = vibrio::syscalls::Fs::open(path_str, flags, mode);
                assert_eq!(rmodel.is_ok(), rtotest.is_ok());

                // Add mapping from rmodel_fd -> rtotest_fd
                if rmodel.is_ok() {
                    fd_map.insert(rmodel.unwrap(), rtotest.unwrap());
                }
            }
            Delete(path) => {
                let path_str = path.join("/");
                let rmodel = model.delete(path_str.as_str());
                let rtotest = vibrio::syscalls::Fs::delete(path_str);
                assert_eq!(rmodel, rtotest);
            }
            Close(fd) => {
                let mut rtotest_fd = fd + FD_OFFSET;
                if fd_map.contains_key(&fd) {
                    rtotest_fd = *fd_map.get(&fd).unwrap();
                }

                let rmodel = model.close(fd);
                let rtotest = vibrio::syscalls::Fs::close(rtotest_fd);
                assert_eq!(rmodel, rtotest);

                // Remove mapping from rmodel_fd -> rtotest_fd
                if rmodel.is_ok() && fd_map.contains_key(&fd) {
                    fd_map.remove(&fd);
                }
            }
        }
    }

    // Clean up file system by closing all open file descriptors and deleting all existing files
    for rtotest_fd in fd_map.values() {
        assert_eq!(vibrio::syscalls::Fs::close(*rtotest_fd).is_ok(), true);
    }
    for x in model.oplog.borrow().iter() {
        match x {
            ModelOperation::Created(path, _modes, mnode) => {
                // mnode=1 is the root ("/") which we can't/shouldn't delete.
                let my_path = path.clone();
                if *mnode != 1 {
                    assert_eq!(vibrio::syscalls::Fs::delete(my_path).is_ok(), true);
                }
            }
            _ => { /* we don't care about write entries */ }
        }
    }
}

pub fn run_fio_syscall_proptests() {
    // Reduce the number of tests so we don't use up all the cache
    proptest!(ProptestConfig::with_cases(100), |(ops in actions())| {
        model_equivalence(ops);
    });
}

/// Create a file with non-read permission and try to read it.
fn test_file_read_permission_error() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_read_permission_error.txt",
        FileFlags::O_WRONLY | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let mut rdata = [0u8; 6];
    assert_eq!(
        vibrio::syscalls::Fs::read(fd, &mut rdata),
        Err(SystemCallError::InternalError)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file with non-write permission and try to write it.
fn test_file_write_permission_error() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_write_permission_error.txt",
        FileFlags::O_RDONLY | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let wdata = [0u8; 6];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, &wdata),
        Err(SystemCallError::InternalError)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file and write to it.
fn test_file_write() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_write.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let wdata = [0u8; 10];
    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(10));
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file, write to it and then later read. Verify the content.
fn test_file_read() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_read.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();

    let wdata = [1u8; 10];
    let mut rdata = [0u8; 10];

    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(10));
    assert_eq!(vibrio::syscalls::Fs::read_at(fd, &mut rdata, 0), Ok(10));
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[9], 1);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file and open again without create permission
fn test_file_duplicate_open() {
    let fd1 = vibrio::syscalls::Fs::open(
        "test_file_duplicate_open.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let fd2 = vibrio::syscalls::Fs::open(
        "test_file_duplicate_open.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    )
    .unwrap();
    assert_ne!(fd1, fd2);
    vibrio::syscalls::Fs::close(fd1).unwrap();
    vibrio::syscalls::Fs::close(fd2).unwrap();
}

/// Attempt to open file that is not present
fn test_file_fake_open() {
    let ret = vibrio::syscalls::Fs::open(
        "test_file_fake_open.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_fake_close() {
    let ret = vibrio::syscalls::Fs::close(10536);
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_duplicate_close() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_duplicate_close.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    assert_eq!(vibrio::syscalls::Fs::close(fd), Ok(()));
    assert_eq!(
        vibrio::syscalls::Fs::close(fd),
        Err(SystemCallError::InternalError)
    );
}

/// Ensure you can write and write with multiple file descriptors
fn test_file_multiple_fd() {
    // Open the same file twice
    let fd1 = vibrio::syscalls::Fs::open(
        "test_file_multiple_fd.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let fd2 = vibrio::syscalls::Fs::open(
        "test_file_multiple_fd.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    )
    .unwrap();

    // Write to file with fd2 & close fd2
    let wdata = [1u8; 10];
    assert_eq!(vibrio::syscalls::Fs::write(fd2, &wdata), Ok(10));
    vibrio::syscalls::Fs::close(fd2).unwrap();

    // Read from file with fd1 & close fd1
    let mut rdata = [0u8; 10];
    assert_eq!(vibrio::syscalls::Fs::read_at(fd1, &mut rdata, 0), Ok(10));
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[9], 1);
    vibrio::syscalls::Fs::close(fd1).unwrap();
}

/// Test file_info.
fn test_file_info() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Get file info
    let ret = vibrio::syscalls::Fs::getinfo("test_file_info.txt");
    assert_eq!(ret, Ok(FileInfo { ftype: 2, fsize: 0 }));
}

/// Test file deletion.
fn test_file_delete() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Delete file
    let ret = vibrio::syscalls::Fs::delete("test_file_info.txt");
    assert!(ret.is_ok());

    // Attempt to open deleted file
    let ret =
        vibrio::syscalls::Fs::open("test_file_info.txt", FileFlags::O_RDWR, FileModes::S_IRWXU);
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn _test_file_delete_open() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();

    // Delete file
    let ret = vibrio::syscalls::Fs::delete("test_file_info.txt");
    assert_eq!(ret, Err(SystemCallError::InternalError));

    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_old.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename("test_file_rename_old.txt", "test_file_rename_new.txt");
    assert_eq!(ret.is_ok(), true);

    // Attempt to open old
    let ret = vibrio::syscalls::Fs::open(
        "test_file_rename_old.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));

    // Attempt to open new
    let ret = vibrio::syscalls::Fs::open(
        "test_file_rename_new.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    );
    assert_eq!(ret.is_ok(), true);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_and_read() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_read_old.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();

    // Write and close
    let wdata = [1u8; 9];
    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(9));
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_and_read_old.txt",
        "test_file_rename_and_read_new.txt",
    );
    assert!(ret.is_ok());

    // Open new
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_read_new.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    )
    .unwrap();

    // Read
    let mut rdata = [0u8; 9];
    assert_eq!(vibrio::syscalls::Fs::read_at(fd, &mut rdata, 0), Ok(9));
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[8], 1);

    // Close
    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_and_write() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_write_old.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_and_write_old.txt",
        "test_file_rename_and_write_new.txt",
    );
    assert!(ret.is_ok());

    // Open new
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_write_old.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();

    // Write
    let wdata = [1u8; 9];
    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(9));

    // Read
    let mut rdata = [0u8; 9];
    assert_eq!(vibrio::syscalls::Fs::read_at(fd, &mut rdata, 0), Ok(9));
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[8], 1);

    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_nonexistent_file() {
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_nonexistent_file_old.txt",
        "test_file_rename_nonexistent_file_new.txt",
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_rename_to_existent_file() {
    // Create existing file & write some data to it & close the fd
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_existing.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let wdata = [1u8; 10];
    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(10));
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Create the old file & write some data to it & close the fd
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_old.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let wdata = [2u8; 10];
    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(10));
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename old file to existing file
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_to_existent_file_old.txt",
        "test_file_rename_to_existent_file_existing.txt",
    );
    assert!(ret.is_ok());

    // Open existing file, check it has old file's data
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_existing.txt",
        FileFlags::O_RDWR,
        FileModes::S_IRWXU,
    )
    .unwrap();
    let mut rdata = [0u8; 10];
    assert_eq!(vibrio::syscalls::Fs::read(fd, &mut rdata), Ok(10));
    assert_eq!(rdata[0], 2);
    assert_eq!(rdata[5], 2);
    assert_eq!(rdata[9], 2);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Tests read_at and write_at
fn test_file_position() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_position.txt",
        FileFlags::O_RDWR | FileFlags::O_CREAT,
        FileModes::S_IRWXU,
    )
    .unwrap();

    let wdata = [1u8; 10];
    let wdata2 = [2u8; 10];
    let mut rdata = [0u8; 10];

    assert_eq!(vibrio::syscalls::Fs::write(fd, &wdata), Ok(10));
    assert_eq!(vibrio::syscalls::Fs::write_at(fd, &wdata2, 5), Ok(10));
    assert_eq!(vibrio::syscalls::Fs::read_at(fd, &mut rdata, 2), Ok(10));
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[2], 1);
    assert_eq!(rdata[3], 2);
    assert_eq!(rdata[9], 2);

    vibrio::syscalls::Fs::close(fd).unwrap();
}

pub fn run_fio_syscall_tests() {
    test_file_read_permission_error();
    test_file_write_permission_error();
    test_file_write();
    test_file_read();
    test_file_duplicate_open();
    test_file_fake_open();
    test_file_fake_close();
    test_file_duplicate_close();
    test_file_multiple_fd();
    test_file_info();
    test_file_delete();
    // TODO: check if this test is correct
    //test_file_delete_open();
    test_file_rename();
    test_file_rename_and_read();
    test_file_rename_and_write();
    test_file_rename_nonexistent_file();
    test_file_rename_to_existent_file();
    test_file_position();
}
