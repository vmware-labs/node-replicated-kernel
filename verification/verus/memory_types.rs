use builtin::*;

pub enum Result<T> {
    Ok(T),
    Err,
}

pub struct PAddr(usize);
pub struct VAddr(usize);
pub struct Frame { base: PAddr, size: usize }
pub struct TlbFlushHandle { base: PAddr, size: usize }

