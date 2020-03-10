//! Test the file-sytem implementation using proptest.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{Eq, PartialEq};
use core::sync::atomic::Ordering;
use core::u64::MAX;

use crate::alloc::borrow::ToOwned;

use proptest::prelude::*;

use kpi::io::*;

use super::*;
use crate::*;

use crate::memory::tcache::TCache;

/// Actions we can perform against the model and the implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestAction {
    Read,
    Write,
    Create,
    Delete,
    Query,
}

/// The FS model that we strive to implement.
struct ModelFS {}

fn actions() -> impl Strategy<Value = Vec<TestAction>> {
    prop::collection::vec(action(), 0..512)
}

fn action() -> impl Strategy<Value = TestAction> {
    prop_oneof![
        Just(TestAction::Read),
        Just(TestAction::Write),
        Just(TestAction::Create),
        Just(TestAction::Delete),
        Just(TestAction::Query),
    ]
}
/*
proptest! {
    // Verify that our implementation behaves according to the `ModelFileSystem`.
    #[test]
    fn model_equivalence(ops in actions()) {
        //let _r = env_logger::try_init();

        use TestAction::*;
        let mut mm = crate::arch::memory::MemoryMapper::new();
        let f = mm.allocate_frame(16 * 1024 * 1024).unwrap();
        let mut tcache = TCache::new_with_frame(0, 0, f);

        let mut totest = fs::MemFS::new();
        let mut model: ModelFS = Default::default();

        for action in ops {
            match action {
                Read => {
                    let rmodel = model.read();
                    let rtotest = totest.read();
                    assert_eq!(rmodel, rtotest);
                }
                Write => {
                    let rmodel = model.write();
                    let rtotest = totest.write();
                    assert_eq!(rmodel, rtotest);
                }
                Create => {
                    let rmodel = model.create();
                    let rtotest = totest.create();
                    assert_eq!(rmodel, rtotest);
                }
                Delete => {
                    let rmodel = model.delete();
                    let rtotest = totest.delete();
                    assert_eq!(rmodel, rtotest);
                }
                Query => {
                    let rmodel = model.query();
                    let rtotest = totest.query();
                    assert_eq!(rmodel, rtotest);
                }
            }
        }
    }
}
*/

/// Initialize and update file descriptor mnode number and permission flags.
#[test]
fn test_file_descriptor() {
    let mut fd = Fd::init_fd();
    assert_eq!(fd.get_mnode(), MAX);
    assert_eq!(fd.get_flags(), FileFlags::O_NONE);

    fd.update_fd(1, FileFlags::O_RDWR);
    assert_eq!(fd.get_mnode(), 1);
    assert_eq!(fd.get_flags(), FileFlags::O_RDWR);
}

/// Initialize memfs for root and verify the values.
#[test]
fn test_memfs_init() {
    let memfs: MemFS = Default::default();
    let root = String::from("/");
    assert_eq!(memfs.root, (root.to_owned(), 1));
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 2);
    assert_eq!(memfs.files.get(&root), Some(&Arc::new(1)));
    assert_eq!(
        memfs.mnodes.get(&1),
        Some(&MemNode::new(1, "/", FileModes::S_IRWXU.into(), NodeType::Directory).unwrap())
    );
}

#[test]
/// Create a file on in-memory fs and verify all the values.
fn test_file_create() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRUSR.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
}

/// Create a file with non-read permission and try to read it.
#[test]

fn test_file_read_permission_error() {
    let buffer = &[0; 10];
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IWUSR.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    // On error read returns 0.
    assert_eq!(
        memfs
            .read(2, &mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
            .is_err(),
        true
    );
}

/// Create a file with non-write permission and try to write it.
#[test]
fn test_file_write_permission_error() {
    let buffer = &[0; 10];
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRUSR.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    // On error read returns 0.
    assert_eq!(
        memfs.write(2, &mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
        Err(FileSystemError::PermissionError)
    );
}

/// Create a file and write to it.
#[test]
fn test_file_write() {
    let buffer = &[0; 10];
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(
        memfs
            .write(2, &mut UserSlice::new(buffer.as_ptr() as u64, 10), -1)
            .unwrap(),
        10
    );
}

/// Create a file, write to it and then later read. Verify the content.
#[test]
fn test_file_read() {
    let len = 10;
    let wbuffer: &[u8; 10] = &[0xb; 10];
    let rbuffer: &mut [u8; 10] = &mut [0; 10];

    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(
        memfs
            .write(2, &mut UserSlice::new(wbuffer.as_ptr() as u64, len), -1)
            .unwrap(),
        len
    );
    assert_eq!(
        memfs
            .read(2, &mut UserSlice::new(rbuffer.as_ptr() as u64, len), -1)
            .unwrap(),
        len
    );
    assert_eq!(rbuffer[0], 0xb);
    assert_eq!(rbuffer[9], 0xb);
}

/// Create a file and lookup for it.
#[test]
fn test_file_lookup() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    let (is_present, mnode) = memfs.lookup(filename);
    assert_eq!(is_present, true);
    assert_eq!(mnode, Some(Arc::new(2)));
}

/// Lookup for a fake file.
#[test]
fn test_file_fake_lookup() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    let (is_present, mnode) = memfs.lookup("filename");
    assert_eq!(is_present, false);
    assert_eq!(mnode, None);
}

/// Try to create a file with same name.
#[test]
fn test_file_duplicate_create() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(
        memfs.create(filename, FileModes::S_IRWXU.into()),
        Err(FileSystemError::AlreadyPresent)
    );
}

/// Test file_info.
#[test]
fn test_file_info() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.nextmemnode.load(Ordering::Relaxed), 3);
    assert_eq!(
        memfs.files.get(&String::from("file.txt")),
        Some(&Arc::new(2))
    );
    assert_eq!(memfs.file_info(2), FileInfo { ftype: 2, fsize: 0 });
}

/// Test file deletion.
#[test]
fn test_file_delete() {
    let mut memfs: MemFS = Default::default();
    let filename = "file.txt";
    let buffer: &mut [u8; 10] = &mut [0xb; 10];

    let mnode = memfs.create(filename, FileModes::S_IRWXU.into()).unwrap();
    assert_eq!(mnode, 2);
    assert_eq!(memfs.delete(filename), Ok(true));
    assert_eq!(memfs.delete(filename).is_err(), true);
    assert_eq!(memfs.lookup(filename), (false, None));
    assert_eq!(
        memfs.write(2, &mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
        Err(FileSystemError::InvalidFile)
    );
    assert_eq!(
        memfs.read(2, &mut UserSlice::new(buffer.as_ptr() as u64, 10), -1),
        Err(FileSystemError::InvalidFile)
    );
}
