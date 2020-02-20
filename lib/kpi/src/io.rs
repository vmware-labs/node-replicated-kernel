/// Modes to create/open the file.
pub const O_RDONLY: u64 = 0x0001; /* open for reading only */
pub const O_WRONLY: u64 = 0x0002; /* open for writing only */
pub const O_RDWR: u64 = 0x0003; /* open for reading and writing */

pub const O_CREAT: u64 = 0x0200; /* create if nonexistant */
pub const O_TRUNC: u64 = 0x0400; /* truncate to zero length */
pub const O_EXCL: u64 = 0x0800; /* error if already exists */

#[macro_export]
macro_rules! is_present {
    ($flags:ident, $flag:ident) => {
        ($flags & $flag != 0)
    };
}
