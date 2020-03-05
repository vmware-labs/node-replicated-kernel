use crate::fs::Modes;
use alloc::vec::Vec;
use x86::bits64::paging::BASE_PAGE_SIZE;

#[derive(Debug, Eq, PartialEq)]
struct Buffer {
    data: Vec<u8>,
}

impl Buffer {
    pub fn try_alloc_buffer() -> Result<Buffer, ()> {
        let mut data = Vec::new();
        match data.try_reserve(BASE_PAGE_SIZE) {
            Ok(_) => Ok(Buffer { data }),
            Err(_) => Err(()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct File {
    mcache: Vec<Buffer>,
    modes: Modes,
    // TODO: Add more file related attributes
}

impl File {
    pub fn new(modes: Modes) -> File {
        File {
            mcache: Vec::with_capacity(128),
            modes,
        }
    }

    pub fn get_size(&self) -> usize {
        let buffer_num = self.mcache.len();
        match buffer_num {
            0 => 0,
            1 => self.mcache[buffer_num - 1].data.len(),
            _ => {
                let mut len = (buffer_num - 1) * BASE_PAGE_SIZE;
                len += self.mcache[buffer_num - 1].data.len();
                len
            }
        }
    }

    pub fn get_mode(&self) -> Modes {
        self.modes
    }

    fn increase_file_size(&mut self, curr_file_len: usize, new_len: usize) -> bool {
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
                let sure_bytes_to_write =
                    free_in_last_buffer + ((new_buffers - 1) * BASE_PAGE_SIZE);
                let bytes_in_last_buffer = new_len - (self.get_size() + sure_bytes_to_write);
                vec.last_mut().unwrap().data.resize(bytes_in_last_buffer, 0);
                self.mcache.append(&mut vec);
                return true;
            }
        }
    }

    fn decrease_file_size(&mut self, new_len: usize) -> bool {
        let buffer_num = self.mcache.len();
        let new_last_buffer = ceil(new_len, BASE_PAGE_SIZE);
        for _i in buffer_num..new_last_buffer {
            self.mcache.pop();
        }
        let extra = (new_last_buffer * BASE_PAGE_SIZE) - new_len;
        let mut keep = 0;
        if extra != 0 {
            keep = BASE_PAGE_SIZE - extra;
        }
        self.mcache.last_mut().unwrap().data.resize(keep, 0);

        true
    }

    pub fn resize_file(&mut self, new_len: usize) -> bool {
        let curr_file_len = self.get_size();
        if curr_file_len == new_len {
            return true;
        }

        match new_len > curr_file_len {
            // Increase the file size
            true => return self.increase_file_size(curr_file_len, new_len),
            // Decrease the file size
            false => return self.decrease_file_size(new_len),
        }
    }

    pub fn read_file(
        &self,
        user_slice: &mut [u8],
        start_offset: usize,
        end_offset: usize,
    ) -> Result<usize, ()> {
        user_slice.copy_from_slice(&self.mcache[0].data[start_offset..end_offset]);
        Ok(end_offset - start_offset)
    }

    pub fn write_file(
        &mut self,
        user_slice: &mut [u8],
        len: usize,
        start_offset: i64,
    ) -> Result<usize, ()> {
        // If offset is specified, then resize the file to the offset + len.
        // If offset is less than file size then truncate the file; otherwise
        // fill the file with zeros till the offset.
        if start_offset != -1 && !self.resize_file(start_offset as usize) {
            return Err(());
        }

        let free_in_last_buffer = match self.mcache.last() {
            Some(buffer) => BASE_PAGE_SIZE - buffer.data.len(),
            None => 0,
        };

        // Add new buffers to the file if the data len is more than free space.
        if len > free_in_last_buffer {
            let add_empty_buffer = ceil(len - free_in_last_buffer, BASE_PAGE_SIZE);
            let mut vec = Vec::with_capacity(add_empty_buffer);
            for _ in 0..add_empty_buffer {
                match Buffer::try_alloc_buffer() {
                    Ok(buffer) => vec.push(buffer),
                    Err(_) => return Err(()),
                }
            }
            self.mcache.append(&mut vec);
        }

        // Write to the allocated buffers
        let mut start = 0;
        let mut end = 0;
        let mut copied = 0;
        let offset = self.get_size();
        let mut buffer_num = offset / BASE_PAGE_SIZE;
        let offset = offset - (buffer_num * BASE_PAGE_SIZE);

        while copied < len {
            let filled = self.mcache[buffer_num].data.len();
            let free_in_buffer = BASE_PAGE_SIZE - filled;
            let remaining = len - copied;
            if free_in_buffer >= remaining {
                end = start + remaining;
            } else {
                end = start + free_in_buffer;
            }
            self.mcache[buffer_num]
                .data
                .append(&mut user_slice[start..end].to_vec());
            buffer_num += 1;
            copied += end - start;
            start = end;
        }

        Ok(len)
    }
}

fn ceil(numerator: usize, denominator: usize) -> usize {
    let mut val = numerator / denominator;
    if numerator > val * denominator {
        val += 1;
    }
    val
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::fs::ALL_PERM;

    #[test]
    /// Initialize a file and check the permissions.
    fn test_init_file() {
        let file = File::new(ALL_PERM);
        assert_eq!(file.modes, ALL_PERM);
        assert_eq!(file.get_size(), 0);
    }
}
