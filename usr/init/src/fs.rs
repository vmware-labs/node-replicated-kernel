// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Test file-system syscall implementation using unit-tests.
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::{Eq, PartialEq};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::alloc::borrow::ToOwned;

use kpi::io::*;
use kpi::SystemCallError;

use log::trace;

/// Create a file with non-read permission and try to read it.
fn test_file_read_permission_error() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_read_permission_error.txt".as_ptr() as u64,
        u64::from(FileFlags::O_WRONLY | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let mut rdata = [0u8; 6];
    assert_eq!(
        vibrio::syscalls::Fs::read(fd, rdata.as_mut_ptr() as u64, 6),
        Err(SystemCallError::InternalError)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file with non-write permission and try to write it.
fn test_file_write_permission_error() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_write_permission_error.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDONLY | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let mut wdata = [0u8; 6];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_mut_ptr() as u64, 6),
        Err(SystemCallError::InternalError)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file and write to it.
fn test_file_write() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_write.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let mut wdata = [0u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file, write to it and then later read. Verify the content.
fn test_file_read() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_read.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    let wdata = [1u8; 10];
    let mut rdata = [0u8; 10];

    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    assert_eq!(
        vibrio::syscalls::Fs::read_at(fd, rdata.as_mut_ptr() as u64, 10, 0),
        Ok(10)
    );
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[9], 1);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Create a file and open again without create permission
fn test_file_duplicate_open() {
    let fd1 = vibrio::syscalls::Fs::open(
        "test_file_duplicate_open.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let fd2 = vibrio::syscalls::Fs::open(
        "test_file_duplicate_open.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    assert_ne!(fd1, fd2);
    vibrio::syscalls::Fs::close(fd1).unwrap();
    vibrio::syscalls::Fs::close(fd2).unwrap();
}

/// Attempt to open file that is not present
fn test_file_fake_open() {
    let ret = vibrio::syscalls::Fs::open(
        "test_file_fake_open.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_fake_close() {
    let ret = vibrio::syscalls::Fs::close(10536);
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_duplicate_close() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_duplicate_close.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    assert_eq!(vibrio::syscalls::Fs::close(fd), Ok(0));
    assert_eq!(
        vibrio::syscalls::Fs::close(fd),
        Err(SystemCallError::InternalError)
    );
}

/// Ensure you can write and write with multiple file descriptors
fn test_file_multiple_fd() {
    // Open the same file twice
    let fd1 = vibrio::syscalls::Fs::open(
        "test_file_multiple_fd.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let fd2 = vibrio::syscalls::Fs::open(
        "test_file_multiple_fd.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    // Write to file with fd2 & close fd2
    let wdata = [1u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd2, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    vibrio::syscalls::Fs::close(fd2).unwrap();

    // Read from file with fd1 & close fd1
    let mut rdata = [0u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::read_at(fd1, rdata.as_mut_ptr() as u64, 10, 0),
        Ok(10)
    );
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[9], 1);
    vibrio::syscalls::Fs::close(fd1).unwrap();
}

/// Test file_info.
fn test_file_info() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Get file info
    let ret = vibrio::syscalls::Fs::getinfo("test_file_info.txt".as_ptr() as u64);
    assert_eq!(ret, Ok(FileInfo { ftype: 2, fsize: 0 }));
}

/// Test file deletion.
fn test_file_delete() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Delete file
    let ret = vibrio::syscalls::Fs::delete("test_file_info.txt".as_ptr() as u64);
    assert_eq!(ret, Ok(true));

    // Attempt to open deleted file
    let ret = vibrio::syscalls::Fs::open(
        "test_file_info.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

/*
fn test_file_delete_open() {
    // Create file
    let fd = vibrio::syscalls::Fs::open(
        "test_file_info.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    // Delete file
    let ret = vibrio::syscalls::Fs::delete("test_file_info.txt".as_ptr() as u64);
    assert_eq!(ret, Err(SystemCallError::InternalError));

    vibrio::syscalls::Fs::close(fd).unwrap();
}
*/

fn test_file_rename() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_old.txt".as_ptr() as u64,
        "test_file_rename_new.txt".as_ptr() as u64,
    );
    assert_eq!(ret.is_ok(), true);

    // Attempt to open old
    let ret = vibrio::syscalls::Fs::open(
        "test_file_rename_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));

    // Attempt to open new
    let ret = vibrio::syscalls::Fs::open(
        "test_file_rename_new.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    );
    assert_eq!(ret.is_ok(), true);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_and_read() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_read_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    // Write and close
    let wdata = [1u8; 9];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 9),
        Ok(9)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_and_read_old.txt".as_ptr() as u64,
        "test_file_rename_and_read_new.txt".as_ptr() as u64,
    );
    assert_eq!(ret, Ok(0));

    // Open new
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_read_new.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    // Read
    let mut rdata = [0u8; 9];
    assert_eq!(
        vibrio::syscalls::Fs::read_at(fd, rdata.as_mut_ptr() as u64, 9, 0),
        Ok(9)
    );
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[8], 1);

    // Close
    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_and_write() {
    // Create old
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_write_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_and_write_old.txt".as_ptr() as u64,
        "test_file_rename_and_write_new.txt".as_ptr() as u64,
    );
    assert_eq!(ret, Ok(0));

    // Open new
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_and_write_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    // Write
    let wdata = [1u8; 9];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 9),
        Ok(9)
    );

    // Read
    let mut rdata = [0u8; 9];
    assert_eq!(
        vibrio::syscalls::Fs::read_at(fd, rdata.as_mut_ptr() as u64, 9, 0),
        Ok(9)
    );
    assert_eq!(rdata[0], 1);
    assert_eq!(rdata[5], 1);
    assert_eq!(rdata[8], 1);

    vibrio::syscalls::Fs::close(fd).unwrap();
}

fn test_file_rename_nonexistent_file() {
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_nonexistent_file_old.txt".as_ptr() as u64,
        "test_file_rename_nonexistent_file_new.txt".as_ptr() as u64,
    );
    assert_eq!(ret, Err(SystemCallError::InternalError));
}

fn test_file_rename_to_existent_file() {
    // Create existing file & write some data to it & close the fd
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_existing.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let wdata = [1u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Create the old file & write some data to it & close the fd
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_old.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let wdata = [2u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    vibrio::syscalls::Fs::close(fd).unwrap();

    // Rename old file to existing file
    let ret = vibrio::syscalls::Fs::rename(
        "test_file_rename_to_existent_file_old.txt".as_ptr() as u64,
        "test_file_rename_to_existent_file_existing.txt".as_ptr() as u64,
    );
    assert_eq!(ret, Ok(0));

    // Open existing file, check it has old file's data
    let fd = vibrio::syscalls::Fs::open(
        "test_file_rename_to_existent_file_existing.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();
    let mut rdata = [2u8; 10];
    assert_eq!(
        vibrio::syscalls::Fs::read(fd, rdata.as_mut_ptr() as u64, 10),
        Ok(10)
    );
    assert_eq!(rdata[0], 2);
    assert_eq!(rdata[5], 2);
    assert_eq!(rdata[9], 2);
    vibrio::syscalls::Fs::close(fd).unwrap();
}

/// Tests read_at and write_at
fn test_file_position() {
    let fd = vibrio::syscalls::Fs::open(
        "test_file_position.txt".as_ptr() as u64,
        u64::from(FileFlags::O_RDWR | FileFlags::O_CREAT),
        FileModes::S_IRWXU.into(),
    )
    .unwrap();

    let wdata = [1u8; 10];
    let wdata2 = [2u8; 10];
    let mut rdata = [0u8; 10];

    assert_eq!(
        vibrio::syscalls::Fs::write(fd, wdata.as_ptr() as u64, 10),
        Ok(10)
    );
    assert_eq!(
        vibrio::syscalls::Fs::write_at(fd, wdata2.as_ptr() as u64, 10, 5),
        Ok(10)
    );
    assert_eq!(
        vibrio::syscalls::Fs::read_at(fd, rdata.as_mut_ptr() as u64, 10, 2),
        Ok(10)
    );
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
