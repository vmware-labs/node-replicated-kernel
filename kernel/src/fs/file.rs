use crate::fs::{FileSystemError, Modes};
use alloc::vec::Vec;
use core::mem::size_of;
use kpi::io::*;
use x86::bits64::paging::BASE_PAGE_SIZE;

#[derive(Debug, Eq, PartialEq)]
/// The buffer is used by the file. Each buffer is BASE_PAGE_SIZE
/// long and a file consists of many such buffers.
struct Buffer {
    data: Vec<u8>,
}

impl Buffer {
    /// This function tries to allocate a vector of BASE_PAGE_SIZE long
    /// and returns a buffer in case of the success; error otherwise.
    pub fn try_alloc_buffer() -> Result<Buffer, FileSystemError> {
        let mut data = Vec::new();
        match data.try_reserve(BASE_PAGE_SIZE) {
            Ok(_) => Ok(Buffer { data }),
            Err(_) => Err(FileSystemError::OutOfMemory),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// File type has a list of buffers and modes to access the file
pub struct File {
    mcache: Vec<Buffer>,
    modes: FileModes,
    // TODO: Add more file related attributes
}

impl File {
    /// Initialize a file. Pre-intialize the buffer list with 64 size.
    pub fn new(modes: Modes) -> Result<File, FileSystemError> {
        let modes = FileModes::from(modes);
        let mut mcache: Vec<Buffer> = Vec::new();
        match mcache.try_reserve(64 * size_of::<Buffer>()) {
            Err(_) => return Err(FileSystemError::OutOfMemory),
            Ok(_) => {}
        }
        Ok(File {
            mcache: mcache,
            modes,
        })
    }

    /// This method returns the current-size of the file. This method follows
    /// the same convention as a vector length. So, size of the file is equal
    /// to the data in it and not the max-allocated buffer-size.
    pub fn get_size(&self) -> usize {
        let buffer_num = self.mcache.len();
        match buffer_num {
            0 => 0,
            1 => self.mcache[buffer_num - 1].data.len(),
            _ => {
                match self.mcache[buffer_num - 1].data.len() {
                    // If resize_file()/write() added some empty buffers to be filled
                    // later, then scan all the buffers to get the file-size.
                    0 => {
                        let mut len = 0;
                        for buf in &self.mcache {
                            match buf.data.len() {
                                0 => break,
                                curr_buff_len => len += curr_buff_len,
                            }
                        }
                        len
                    }
                    // If file is filled till last buffer
                    last_buffer_len => ((buffer_num - 1) * BASE_PAGE_SIZE + last_buffer_len),
                }
            }
        }
    }

    /// This method returns the mode in which file is created.
    pub fn get_mode(&self) -> FileModes {
        self.modes
    }

    /// This method is internally used by write_file() method. The additional length
    /// is initialzed to zero.
    pub fn increase_file_size(&mut self, curr_file_len: usize, new_len: usize) -> bool {
        if new_len == 0 {
            return true;
        }

        let free_in_last_buffer = match self.mcache.last() {
            Some(buffer) => BASE_PAGE_SIZE - buffer.data.len(),
            None => 0,
        };

        let add_new = new_len - curr_file_len;
        match add_new <= free_in_last_buffer {
            // Don't need to add new buffer
            true => {
                let offset = self.mcache.last().unwrap().data.len();
                self.mcache
                    .last_mut()
                    .unwrap()
                    .data
                    .resize(offset + add_new, 0);
                return true;
            }

            // Add new buffer
            false => {
                if self.mcache.len() > 0 {
                    self.mcache
                        .last_mut()
                        .unwrap()
                        .data
                        .resize(BASE_PAGE_SIZE, 0);
                }
                let remaining = add_new - free_in_last_buffer;
                let new_buffers = ceil(remaining, BASE_PAGE_SIZE);
                let mut vec = Vec::with_capacity(new_buffers);
                for _i in 0..new_buffers {
                    match Buffer::try_alloc_buffer() {
                        Ok(mut buffer) => {
                            buffer.data.resize(BASE_PAGE_SIZE, 0);
                            vec.push(buffer);
                        }
                        Err(_) => return false,
                    }
                }

                // Filled all the buffers with zeros, resize the last buffer.
                if new_len % BASE_PAGE_SIZE != 0 {
                    let sure_bytes_to_write = (new_buffers - 1) * BASE_PAGE_SIZE;
                    let bytes_in_last_buffer = new_len - (self.get_size() + sure_bytes_to_write);
                    vec.last_mut().unwrap().data.resize(bytes_in_last_buffer, 0);
                }
                self.mcache.append(&mut vec);
                return true;
            }
        }
    }

    /// This method is internally call on a read() system-call. It reads the content of the
    /// file and copies it in a user provided slice. The data is read from start_offset till
    /// end_offset(not inclusive).
    pub fn read_file(
        &self,
        user_slice: &mut [u8],
        start_offset: usize,
        end_offset: usize,
    ) -> Result<usize, FileSystemError> {
        let mut buffer_num = offset_to_buffernum(start_offset, BASE_PAGE_SIZE);
        let mut offset_in_buffer = start_offset - (buffer_num * BASE_PAGE_SIZE);
        let mut copied = 0;
        let mut dst_start = 0;
        let mut dst_end;

        let len = end_offset - start_offset;
        while copied < len {
            let useful_data_curr_buffer = self.mcache[buffer_num].data.len() - offset_in_buffer;
            let remaining = len - copied;

            let src_start = offset_in_buffer;
            let src_end;
            if remaining >= useful_data_curr_buffer {
                dst_end = dst_start + useful_data_curr_buffer;
                src_end = src_start + useful_data_curr_buffer;
                copied += useful_data_curr_buffer;
            } else {
                dst_end = dst_start + remaining;
                src_end = src_start + remaining;
                copied += remaining;
            }
            user_slice[dst_start..dst_end]
                .copy_from_slice(&self.mcache[buffer_num].data[src_start..src_end]);
            buffer_num += 1;
            dst_start = dst_end;
            offset_in_buffer = 0;
        }

        Ok(copied)
    }

    /// This method is internally called on a write() system-call. The user provided the
    /// data in a user-slice and the method copies that data into the file buffers. Beside
    /// the slice the user also provides the length of the data and it can also specify an
    /// arbitrary offset in the file to write the data.
    pub fn write_file(
        &mut self,
        user_slice: &[u8],
        len: usize,
        start_offset: usize,
    ) -> Result<usize, FileSystemError> {
        // If offset is specified, then resize the file to the offset + len.
        // If offset is more than file size then fill the file with zeros till the offset.
        let curr_file_len = self.get_size();
        let new_len = start_offset + len;
        if new_len > curr_file_len {
            if new_len > 0 && !self.increase_file_size(curr_file_len, new_len) {
                return Err(FileSystemError::OutOfMemory);
            }
        }

        let mut buffer_num = offset_to_buffernum(start_offset, BASE_PAGE_SIZE);
        let mut offset_in_buffer = start_offset - (buffer_num * BASE_PAGE_SIZE);
        let mut copied = 0;
        let mut dst_start = 0;
        let mut dst_end;

        while copied < len {
            let useful_data_curr_buffer = BASE_PAGE_SIZE - offset_in_buffer;
            let remaining = len - copied;

            let src_start = offset_in_buffer;
            let src_end;
            if remaining >= useful_data_curr_buffer {
                dst_end = dst_start + useful_data_curr_buffer;
                src_end = src_start + useful_data_curr_buffer;
                copied += useful_data_curr_buffer;
            } else {
                dst_end = dst_start + remaining;
                src_end = src_start + remaining;
                copied += remaining;
            }

            self.mcache[buffer_num].data[src_start..src_end]
                .copy_from_slice(&user_slice[dst_start..dst_end]);
            buffer_num += 1;
            dst_start = dst_end;
            offset_in_buffer = 0;
        }

        Ok(len)
    }

    /// Truncate the file in reasponse of O_TRUNC flag.
    pub fn file_truncate(&mut self) {
        self.mcache.clear();
    }
}

/// This is used to determine, how many buffers to add dependeing on the number
/// of bytes and buffer-size.
fn ceil(bytes: usize, buffer_size: usize) -> usize {
    let mut val = bytes / buffer_size;
    if bytes > val * buffer_size {
        val += 1;
    }
    val
}

/// This method converts the file offset to buffer number with-in a file.
/// The assumption is that the buffer-size is equal for all the buffers
/// in a file.
fn offset_to_buffernum(offset: usize, buffer_size: usize) -> usize {
    offset / buffer_size
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    /// This method test the offset to buffer number conversion for a file.
    /// It uses BASE_PAGE_SIZE as buffer size.
    fn test_offset_to_buffernum() {
        let mut buffer_num: i64 = -1;
        for i in 0..10000 {
            if (i % BASE_PAGE_SIZE) == 0 {
                buffer_num += 1;
            }
            assert_eq!(offset_to_buffernum(i, BASE_PAGE_SIZE), buffer_num as usize);
        }
    }

    #[test]
    /// This method tests the ceil method.
    fn test_ceil() {
        let mut cval = 0;
        for i in 0..10000 {
            assert_eq!(ceil(i, BASE_PAGE_SIZE), cval as usize);
            if (i % BASE_PAGE_SIZE) == 0 {
                cval += 1;
            }
        }
    }

    #[test]
    /// This method test the size of the allocated buffer.
    fn test_buffer_alloc() {
        let buffer = Buffer::try_alloc_buffer().unwrap();
        assert_eq!(buffer.data.len(), 0);
        assert_eq!(buffer.data.capacity(), BASE_PAGE_SIZE);
    }

    #[test]
    /// Initialize a file and check the permissions.
    fn test_init_file() {
        let file = File::new(FileModes::S_IRWXU.into()).unwrap();
        assert_eq!(file.get_mode(), FileModes::S_IRWXU);
        assert_eq!(file.get_size(), 0);
        assert_eq!(file.mcache.len(), 0);
        assert_eq!(file.mcache.capacity(), 64 * size_of::<Buffer>());
    }

    #[test]
    /// This tests the resize file method.
    fn test_resize_file() {
        let mut file = File::new(FileModes::S_IRWXU.into()).unwrap();
        assert_eq!(file.get_mode(), FileModes::S_IRWXU);
        assert_eq!(file.mcache.len(), 0);
        assert_eq!(file.mcache.capacity(), 64 * size_of::<Buffer>());

        assert_eq!(file.get_size(), 0);

        for i in 0..10000 {
            assert_eq!(file.increase_file_size(file.get_size(), i), true);
            assert_eq!(file.get_size(), i);
            let buffer_num = ceil(i, BASE_PAGE_SIZE);
            assert_eq!(file.mcache.len(), buffer_num);
        }
    }

    #[test]
    /// Tests the writing to a file and later check if the content was written properly or not.
    fn test_write_file() {
        let mut file = File::new(FileModes::S_IRWXU.into()).unwrap();
        assert_eq!(file.get_mode(), FileModes::S_IRWXU);
        assert_eq!(file.mcache.len(), 0);
        assert_eq!(file.mcache.capacity(), 64 * size_of::<Buffer>());

        let buffer: &mut [u8] = &mut [0xb; 10000];
        for i in 0..10000 {
            file.write_file(buffer, i, 0).unwrap();
            assert_eq!(file.get_size(), i);
        }

        // verify the content for first buffer
        for i in 0..4096 {
            assert_eq!(file.mcache[0].data[i], 0xb);
        }
    }

    #[test]
    /// This test writes to the file and later it reads and verifies the content of the file.
    fn test_read_file() {
        let mut file = File::new(FileModes::S_IRWXU.into()).unwrap();
        assert_eq!(file.get_mode(), FileModes::S_IRWXU);
        assert_eq!(file.mcache.len(), 0);
        assert_eq!(file.mcache.capacity(), 64 * size_of::<Buffer>());

        let wbuffer: &mut [u8] = &mut [0xb; 10000];
        let rbuffer: &mut [u8] = &mut [0; 10000];

        assert_eq!(file.write_file(wbuffer, 10000, 0), Ok(10000));
        assert_eq!(file.get_size(), 10000);

        for i in 0..10000 {
            file.read_file(&mut rbuffer[i..i + 1], i, i + 1).unwrap();
            assert_eq!(rbuffer[i], 0xb);
        }
    }

    #[test]
    /// This test checks if the file truncation works as expected.
    fn test_file_truncate() {
        let mut file = File::new(FileModes::S_IRWXU.into()).unwrap();
        let wbuffer: &mut [u8] = &mut [0xb; 10000];

        assert_eq!(file.write_file(wbuffer, 10000, 0), Ok(10000));
        assert_eq!(file.get_size(), 10000);

        file.file_truncate();
        assert_eq!(file.get_size(), 0);
        assert_eq!(file.mcache.len(), 0);
    }

    #[test]
    /// Tests the writing to a file and later check if the content was written properly or not.
    fn test_overwrite_file() {
        let mut file = File::new(FileModes::S_IRWXU.into()).unwrap();
        assert_eq!(file.get_mode(), FileModes::S_IRWXU);
        assert_eq!(file.mcache.len(), 0);
        assert_eq!(file.mcache.capacity(), 64 * size_of::<Buffer>());

        let buffer: &mut [u8] = &mut [0xb; 10000];
        for i in 0..10000 {
            file.write_file(buffer, i, 0).unwrap();
            assert_eq!(file.get_size(), i);
        }

        let buffer: &mut [u8] = &mut [0xa; 7000];
        for i in 0..4096 {
            file.write_file(buffer, i, 0).unwrap();
            assert_eq!(file.get_size(), 9999);
        }

        // verify the content for first buffer
        for i in 0..4095 {
            assert_eq!(file.mcache[0].data[i], 0xa);
        }
        // verify the content for second buffer
        for i in 0..4096 {
            assert_eq!(file.mcache[1].data[i], 0xb);
        }
    }
}
