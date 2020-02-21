/// Flags to create/open the file.
pub const O_RDONLY: u64 = 0x0001; /* open for reading only */
pub const O_WRONLY: u64 = 0x0002; /* open for writing only */
pub const O_RDWR: u64 = 0x0003; /* open for reading and writing */

pub const O_CREAT: u64 = 0x0200; /* create if nonexistant */
pub const O_TRUNC: u64 = 0x0400; /* truncate to zero length */
pub const O_EXCL: u64 = 0x0800; /* error if already exists */

/// Modes for the opened file
pub const S_IRWXU: u64 = 0x700; /* RWX mask for owner */
pub const S_IRUSR: u64 = 0x400; /* R for owner */
pub const S_IWUSR: u64 = 0x200; /* W for owner */
pub const S_IXUSR: u64 = 0x100; /* X for owner */

pub const S_IRWXG: u64 = 0x070; /* RWX mask for group */
pub const S_IRGRP: u64 = 0x040; /* R for group */
pub const S_IWGRP: u64 = 0x020; /* W for group */
pub const S_IXGRP: u64 = 0x010; /* X for group */

pub const S_IRWXO: u64 = 0x007; /* RWX mask for other */
pub const S_IROTH: u64 = 0x004; /* R for other */
pub const S_IWOTH: u64 = 0x002; /* W for other */
pub const S_IXOTH: u64 = 0x001; /* X for other */

pub const ALL_PERM: u64 = 0x777;

#[macro_export]
macro_rules! is_allowed {
    ($flags:expr, $flag:ident) => {
        ($flags & $flag == $flag)
    };
}
