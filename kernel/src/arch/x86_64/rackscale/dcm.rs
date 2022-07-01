#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocRequest {
    pub application: u64,
    pub cores: u64,
    pub memslices: u64,
}
pub const REQ_SIZE: usize = core::mem::size_of::<AllocRequest>();

impl AllocRequest {
    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; REQ_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocRequest) as *mut u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocRequest
    pub unsafe fn as_bytes(&self) -> &[u8; REQ_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocRequest) as *const u8, REQ_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocResponse {
    pub alloc_id: u64,
}
pub const RES_SIZE: usize = core::mem::size_of::<AllocResponse>();

impl AllocResponse {
    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; RES_SIZE] {
        ::core::slice::from_raw_parts_mut((self as *const AllocResponse) as *mut u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocResponse
    pub unsafe fn as_bytes(&self) -> &[u8; RES_SIZE] {
        ::core::slice::from_raw_parts((self as *const AllocResponse) as *const u8, RES_SIZE)
            .try_into()
            .expect("slice with incorrect length")
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocAssignment {
    pub alloc_id: u64,
    pub node: u64,
}
pub const ALLOC_LEN: usize = core::mem::size_of::<AllocAssignment>();

impl AllocAssignment {
    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_mut_bytes(&mut self) -> &mut [u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts_mut((self as *const AllocAssignment) as *mut u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }

    /// # Safety
    /// - `self` must be valid AllocAssignment
    pub unsafe fn as_bytes(&self) -> &[u8; ALLOC_LEN] {
        ::core::slice::from_raw_parts((self as *const AllocAssignment) as *const u8, ALLOC_LEN)
            .try_into()
            .expect("slice with incorrect length")
    }
}
