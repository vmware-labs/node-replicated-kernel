// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Test file-system syscall implementation using unit-tests and proptest.
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::{Eq, PartialEq};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{AtomicUsize, Ordering};
use cstr_core::CStr;

use crate::alloc::borrow::ToOwned;

use kpi::io::*;
use kpi::SystemCallError;
use x86::bits64::paging::{PAddr, VAddr};

use log::trace;
use proptest::prelude::*;

pub type Mnode = u64;

const MAX_FILES_PER_PROCESS: usize = 4096;

pub fn userptr_to_str(useraddr: u64) -> Result<String, SystemCallError> {
    let user_ptr = VAddr::from(useraddr);
    unsafe {
        match CStr::from_ptr(user_ptr.as_ptr()).to_str() {
            Ok(path) => Ok(path.to_string()),
            Err(_) => Err(SystemCallError::NotSupported),
        }
    }
}

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
struct Fd {
    mnode: Mnode,
    flags: FileFlags,
    offset: AtomicUsize,
}

impl Fd {
    fn init_fd() -> Fd {
        Fd {
            // Intial values are just the place-holders and shouldn't be used.
            mnode: u64::MAX,
            flags: Default::default(),
            offset: AtomicUsize::new(0),
        }
    }

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
            Err(SystemCallError::InternalError)
        }
    }

    pub fn deallocate_fd(&mut self, fd: u64) -> Result<u64, SystemCallError> {
        match self.fds.get_mut(fd as usize) {
            Some(fdinfo) => {
                *fdinfo = None;
                Ok(fd)
            }
            None => Err(SystemCallError::InternalError),
        }
    }

    pub fn get_fd(&self, index: usize) -> Result<&Fd, SystemCallError> {
        if let Some(fd) = self.fds[index].as_ref() {
            Ok(fd)
        } else {
            Err(SystemCallError::InternalError)
        }
    }

    pub fn find_fd(&self, mnode: Mnode) -> Option<u64> {
        if let Some(fid) = self.fds.iter().position(|fd_pos| {
            if let Some(fd) = &&fd_pos {
                fd.get_mnode() == mnode
            } else {
                false
            }
        }) {
            Some(fid as u64)
        } else {
            None
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

    /// Check if a given path exists.
    fn file_exists(&self, path: &String) -> bool {
        self.path_to_mnode(path).is_some()
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
    pub fn open(&mut self, pathname: u64, flags: u64, modes: u64) -> Result<u64, SystemCallError> {
        let path = userptr_to_str(pathname)?;
        let flags = FileFlags::from(flags);

        // If file exists, only create new fd
        if let Some(mnode) = self.lookup(&path) {
            if flags.is_create() {
                Err(SystemCallError::InternalError)
            } else {
                let (fid, fd) = self.fds.allocate_fd()?;
                fd.update_fd(*self.mnode_counter.borrow(), flags);

                if flags.is_append() {
                    // TODO: if append, set position to end of file
                }
                if flags.is_truncate() {
                    // TODO: truncate length of file
                }

                Ok(fid)
            }

        // Create new file if necessary
        } else {
            if !flags.is_create() {
                return Err(SystemCallError::InternalError);
            }

            *self.mnode_counter.borrow_mut() += 1;
            self.oplog.borrow_mut().push(ModelOperation::Created(
                path,
                FileModes::from(modes),
                *self.mnode_counter.borrow(),
            ));
            let (fid, fd) = self.fds.allocate_fd()?;
            fd.update_fd(*self.mnode_counter.borrow(), flags);
            Ok(fid)
        }
    }

    pub fn write(&self, fid: u64, buffer: u64, len: u64) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong... should be InternalError??
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let fd = self.fds.get_fd(fid as usize)?;
        self.write_at(fid, buffer, len, fd.get_offset() as i64)
    }

    /// Write just logs the write to the oplog.
    ///
    /// Our model assumes that the buffer repeats the first byte for its entire length.
    pub fn write_at(
        &self,
        fid: u64,
        buffer: u64,
        len: u64,
        offset: i64,
    ) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong... should be InternalError??
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let mut fd = self.fds.get_fd(fid as usize)?;
        let flags = fd.get_flags();

        // check for write permissions
        if !flags.is_write() {
            return Err(SystemCallError::InternalError);
        }

        let mnode = fd.get_mnode();
        if self.mnode_exists(mnode) {
            for x in self.oplog.borrow().iter().rev() {
                trace!("seen {:?}", x);
                match x {
                    // Check if the file is writable or not
                    ModelOperation::Created(_path, mode, current_mnode) => {
                        if mnode == *current_mnode && !FileModes::from(*mode).is_writable() {
                            return Err(SystemCallError::InternalError);
                        }
                    }
                    _ => { /* The operation is not relevant */ }
                }
            }

            if len > 0 {
                // Model assumes that buffer is filled with the same pattern all the way
                let slice = unsafe { from_raw_parts(buffer as *const u8, 1) };
                let pattern = slice[0] as char;
                self.oplog
                    .borrow_mut()
                    .push(ModelOperation::Write(mnode, offset, pattern, len));
            }
            fd.update_offset(offset as usize + len as usize);
            Ok(len)
        } else {
            Err(SystemCallError::InternalError)
        }
    }

    pub fn read(&self, fid: u64, buffer: u64, len: u64) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong... should be InternalError??
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let fd = self.fds.get_fd(fid as usize)?;
        self.read_at(fid, buffer, len, fd.get_offset() as i64)
    }

    /// read loops through the oplog and tries to fill up the buffer by looking
    /// at the logged `Write` ops.
    ///
    /// This is the hardest operation to represent in the model.
    pub fn read_at(
        &self,
        fid: u64,
        buffer: u64,
        len: u64,
        offset: i64,
    ) -> Result<u64, SystemCallError> {
        // TODO: this seems wrong, should be internal Error??
        if len == 0 {
            return Err(SystemCallError::BadFileDescriptor);
        }

        let fd = self.fds.get_fd(fid as usize)?;
        let flags = fd.get_flags();

        // check for read permissions
        if !flags.is_read() {
            return Err(SystemCallError::InternalError);
        }

        let mnode = fd.get_mnode();
        if self.mnode_exists(mnode) {
            // We store our 'retrieved' data in a buffer of Option<u8>
            // to make sure in case we have consecutive writes to the same region
            // we take the last one, and also to detect if we
            // read more than what ever got written to the file...
            let mut buffer_gatherer: Vec<Option<u8>> = Vec::with_capacity(len as usize);
            for _i in 0..len {
                buffer_gatherer.push(None);
            }

            // Start with the latest writes first
            for x in self.oplog.borrow().iter().rev() {
                trace!("seen {:?}", x);
                match x {
                    ModelOperation::Write(wmnode, foffset, fpattern, flength) => {
                        // Write is for the correct file and the offset starts somewhere
                        // in that write
                        let cur_segment_range =
                            *foffset as usize..(*foffset as usize + *flength as usize);
                        let read_range = offset as usize..(offset as usize + len as usize);
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

                    ModelOperation::Created(_path, mode, cmnode) => {
                        if mnode == *cmnode && !FileModes::from(*mode).is_readable() {
                            return Err(SystemCallError::InternalError);
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
            let mut slice = unsafe { from_raw_parts_mut(buffer as *mut u8, len as usize) };
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

                slice[idx] = val.unwrap_or(0);
                trace!("buffer = {:?}", slice);
            }

            fd.update_offset(offset as usize + len as usize);
            Ok(bytes_read)
        } else {
            Err(SystemCallError::InternalError)
        }
    }

    /// Lookup just returns the mnode.
    fn lookup(&self, pathname: &str) -> Option<Mnode> {
        self.path_to_mnode(&String::from(pathname))
    }

    /// Delete finds sand removes a path from the oplog again.
    pub fn delete(&self, name: u64) -> Result<bool, SystemCallError> {
        let path = userptr_to_str(name)?;
        if let Some(mnode) = self.lookup(&path) {
            // Check to see if there are any open fds to this mnode.
            // If not, we delete the file.
            if let Err(_) = self.fds.get_fd(mnode as usize) {
                if let Some(idx) = self.path_to_idx(&path) {
                    self.oplog.borrow_mut().remove(idx);
                    // We leave corresponding ModelOperation::Write entries
                    // in the log for now...
                    return Ok(true);
                }
            }
        }
        Err(SystemCallError::InternalError)
    }

    pub fn close(&mut self, fd: u64) -> Result<u64, SystemCallError> {
        self.fds.deallocate_fd(fd)?;
        Ok(0)
    }
}

/// Two writes/reads at different offsets should return
/// the correct result.
fn model_read() {
    let mut mfs: ModelFIO = Default::default();
    let fd = mfs
        .open(
            "/bla".as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            FileModes::S_IRWXU.into(),
        )
        .unwrap();

    let mut wdata1: [u8; 2] = [1, 1];
    let r = mfs.write_at(fd, wdata1.as_ptr() as u64, 2, 0);
    assert_eq!(r, Ok(2));

    let mut wdata: [u8; 2] = [2, 2];
    let r = mfs.write_at(fd, wdata.as_ptr() as u64, 2, 2);
    assert_eq!(r, Ok(2));

    let mut rdata: [u8; 2] = [0, 0];

    let r = mfs.read_at(fd, rdata.as_ptr() as u64, 2, 0);
    assert_eq!(rdata, [1, 1]);
    assert_eq!(r, Ok(2));

    let r = mfs.read_at(fd, rdata.as_ptr() as u64, 2, 2);
    assert_eq!(rdata, [2, 2]);
    assert_eq!(r, Ok(2));
}

/// Two writes that overlap with each other should return
/// the last write.
///
/// Also providing a larger buffer returns 0 in those entries.
fn model_overlapping_writes() {
    let mut mfs: ModelFIO = Default::default();
    let fd = mfs
        .open(
            "/bla".as_ptr() as u64,
            u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
            FileModes::S_IRWXU.into(),
        )
        .unwrap();

    let mut data: [u8; 3] = [1, 1, 1];
    let r = mfs.write(fd, data.as_ptr() as u64, 3);
    assert_eq!(r, Ok(3));

    let mut wdata: [u8; 3] = [2, 2, 2];
    let r = mfs.write_at(fd, wdata.as_ptr() as u64, 3, 2);

    let mut rdata: [u8; 6] = [0, 0, 0, 0, 0, 0];
    let r = mfs.read_at(fd, rdata.as_ptr() as u64, 5, 0);
    assert_eq!(r, Ok(5));
    assert_eq!(rdata, [1, 1, 2, 2, 2, 0]);
}

/// Actions that we can perform against the model and the implementation.
///
/// One entry for each function in the FileSystem interface and
/// necessary arguments to construct an operation for said function.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TestAction {
    Read(u64, u64),
    Write(u64, char, u64),
    ReadAt(u64, u64, i64),
    WriteAt(u64, char, u64, i64),
    Open(Vec<String>, u64, u64),
    Delete(Vec<String>),
    Close(u64),
}

/// Generates one `TestAction` entry randomly.
fn action() -> impl Strategy<Value = TestAction> {
    prop_oneof![
        (fd_gen(0x10), size_gen(128)).prop_map(|(a, c)| TestAction::Read(a, c)),
        (fd_gen(0x10), fill_pattern(), size_gen(64))
            .prop_map(|(a, c, d)| TestAction::Write(a, c, d)),
        (fd_gen(0x10), size_gen(128), offset_gen(0x1000))
            .prop_map(|(a, b, c)| TestAction::ReadAt(a, b, c)),
        (
            fd_gen(0x10),
            fill_pattern(),
            size_gen(64),
            offset_gen(0x1000),
        )
            .prop_map(|(a, b, c, d)| TestAction::WriteAt(a, b, c, d)),
        (path(), flag_gen(0xfff), mode_gen(0xfff)).prop_map(|(a, b, c)| TestAction::Open(a, b, c)),
        path().prop_map(TestAction::Delete),
        fd_gen(0x10).prop_map(TestAction::Close),
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
    fn size_gen(max: u64)(size in 0..max) -> u64 { size }
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

// Verify that our FS implementation behaves according to the `ModelFileSystem`.
fn model_equivalence(ops: Vec<TestAction>) {
    let mut model: ModelFIO = Default::default();

    use TestAction::*;
    for action in ops {
        log::debug!("{:?}", action);
        match action {
            Read(fd, len) => {
                let mut buffer1: Vec<u8> = Vec::with_capacity(len as usize);
                let mut buffer2: Vec<u8> = Vec::with_capacity(len as usize);

                let rmodel = model.read(fd, buffer1.as_mut_ptr() as u64, len);
                let rtotest = vibrio::syscalls::Fs::read(fd, buffer2.as_mut_ptr() as u64, len);
                assert_eq!(rmodel, rtotest);
                assert_eq!(buffer1, buffer2);
            }
            Write(fd, pattern, len) => {
                let mut buffer: Vec<u8> = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    buffer.push(pattern as u8);
                }

                let rmodel = model.write(fd, buffer.as_mut_ptr() as u64, len);
                let rtotest = vibrio::syscalls::Fs::write(fd, buffer.as_mut_ptr() as u64, len);
                assert_eq!(rmodel, rtotest);
            }
            ReadAt(fd, len, offset) => {
                let mut buffer1: Vec<u8> = Vec::with_capacity(len as usize);
                let mut buffer2: Vec<u8> = Vec::with_capacity(len as usize);

                let rmodel = model.read_at(fd, buffer1.as_mut_ptr() as u64, len, offset);
                let rtotest =
                    vibrio::syscalls::Fs::read_at(fd, buffer1.as_mut_ptr() as u64, len, offset);
                assert_eq!(rmodel, rtotest);
                assert_eq!(buffer1, buffer2);
            }
            WriteAt(fd, pattern, len, offset) => {
                let mut buffer: Vec<u8> = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    buffer.push(pattern as u8);
                }

                let rmodel = model.write_at(fd, buffer.as_mut_ptr() as u64, len, offset);
                let rtotest =
                    vibrio::syscalls::Fs::write_at(fd, buffer.as_mut_ptr() as u64, len, offset);
                assert_eq!(rmodel, rtotest);
            }
            Open(path, flags, mode) => {
                let path_str = path.join("/");
                let rmodel = model.open(path_str.as_ptr() as u64, flags, mode);
                let rtotest = vibrio::syscalls::Fs::open(path_str.as_ptr() as u64, flags, mode);
                assert_eq!(rmodel, rtotest);
            }
            Delete(path) => {
                let path_str = path.join("/");

                let rmodel = model.delete(path_str.as_ptr() as u64);
                let rtotest = vibrio::syscalls::Fs::delete(path_str.as_ptr() as u64);
                assert_eq!(rmodel, rtotest);
            }
            Close(fd) => {
                let rmodel = model.close(fd);
                let rtotest = vibrio::syscalls::Fs::close(fd);
                assert_eq!(rmodel, rtotest);
            }
        }
    }
}

pub fn run_fio_syscall_tests() {
    model_read();
    model_overlapping_writes();

    // TODO: run properties tests
    proptest!( |(ops in actions())| {
        model_equivalence(ops);
    });
}
