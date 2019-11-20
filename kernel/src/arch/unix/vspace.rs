use crate::alloc::string::ToString;
use alloc::boxed::Box;

use core::fmt;
use core::pin::Pin;

use custom_error::custom_error;
use x86::bits64::paging::*;

use kpi::SystemCallError;

custom_error! {pub VSpaceError
    AlreadyMapped{from: u64, to: u64} = "VSpace operation covers existing mapping ({from} -- {to})",
}

impl Into<SystemCallError> for VSpaceError {
    fn into(self) -> SystemCallError {
        match self {
            VSpaceError::AlreadyMapped { from: _, to: _ } => SystemCallError::VSpaceAlreadyMapped,
        }
    }
}

/// Mapping rights to give to address translation.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(unused)]
pub enum MapAction {
    /// Don't map
    None,
    /// Map region read-only.
    ReadUser,
    /// Map region read-only for kernel.
    ReadKernel,
    /// Map region read-write.
    ReadWriteUser,
    /// Map region read-write for kernel.
    ReadWriteKernel,
    /// Map region read-executable.
    ReadExecuteUser,
    /// Map region read-executable for kernel.
    ReadExecuteKernel,
    /// Map region read-write-executable.
    ReadWriteExecuteUser,
    /// Map region read-write-executable for kernel.
    ReadWriteExecuteKernel,
}

/// Type of resource we're trying to allocate
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResourceType {
    /// ELF Binary data
    Binary,
    /// Physical memory
    Memory,
    /// Page-table meta-data
    PageTable,
}

impl MapAction {
    /// Transform MapAction into rights for 1 GiB page.
    fn to_pdpt_rights(&self) -> PDPTFlags {
        use MapAction::*;
        match self {
            None => PDPTFlags::empty(),
            ReadUser => PDPTFlags::XD | PDPTFlags::US,
            ReadKernel => PDPTFlags::XD,
            ReadWriteUser => PDPTFlags::RW | PDPTFlags::XD | PDPTFlags::US,
            ReadWriteKernel => PDPTFlags::RW | PDPTFlags::XD,
            ReadExecuteUser => PDPTFlags::US,
            ReadExecuteKernel => PDPTFlags::empty(),
            ReadWriteExecuteUser => PDPTFlags::RW | PDPTFlags::US,
            ReadWriteExecuteKernel => PDPTFlags::RW,
        }
    }

    /// Transform MapAction into rights for 2 MiB page.
    fn to_pd_rights(&self) -> PDFlags {
        use MapAction::*;
        match self {
            None => PDFlags::empty(),
            ReadUser => PDFlags::XD | PDFlags::US,
            ReadKernel => PDFlags::XD,
            ReadWriteUser => PDFlags::RW | PDFlags::XD | PDFlags::US,
            ReadWriteKernel => PDFlags::RW | PDFlags::XD,
            ReadExecuteUser => PDFlags::US,
            ReadExecuteKernel => PDFlags::empty(),
            ReadWriteExecuteUser => PDFlags::RW | PDFlags::US,
            ReadWriteExecuteKernel => PDFlags::RW,
        }
    }

    /// Transform MapAction into rights for 4KiB page.
    fn to_pt_rights(&self) -> PTFlags {
        use MapAction::*;
        match self {
            None => PTFlags::empty(),
            ReadUser => PTFlags::XD | PTFlags::US,
            ReadKernel => PTFlags::XD,
            ReadWriteUser => PTFlags::RW | PTFlags::XD | PTFlags::US,
            ReadWriteKernel => PTFlags::RW | PTFlags::XD,
            ReadExecuteUser => PTFlags::US,
            ReadExecuteKernel => PTFlags::empty(),
            ReadWriteExecuteUser => PTFlags::RW | PTFlags::US,
            ReadWriteExecuteKernel => PTFlags::RW,
        }
    }
}

impl fmt::Display for MapAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use MapAction::*;
        match self {
            None => write!(f, " ---"),
            ReadUser => write!(f, "uR--"),
            ReadKernel => write!(f, "kR--"),
            ReadWriteUser => write!(f, "uRW-"),
            ReadWriteKernel => write!(f, "kRW-"),
            ReadExecuteUser => write!(f, "uR-X"),
            ReadExecuteKernel => write!(f, "kR-X"),
            ReadWriteExecuteUser => write!(f, "uRWX"),
            ReadWriteExecuteKernel => write!(f, "kRWX"),
        }
    }
}

pub struct VSpace {
    pub pml4: Pin<Box<PML4>>,
}

impl VSpace {
    pub fn new() -> VSpace {
        VSpace {
            pml4: Box::pin(
                [PML4Entry::new(PAddr::from(0x0u64), PML4Flags::empty()); PAGE_SIZE_ENTRIES],
            ),
        }
    }

    pub fn map_identity(&mut self, base: VAddr, end: VAddr) {
        unreachable!("map_identity 0x{:x} -- 0x{:x}", base, end);
    }

    pub fn map(
        &mut self,
        base: VAddr,
        size: usize,
        rights: MapAction,
        palignment: u64,
    ) -> Result<(PAddr, usize), VSpaceError> {
        assert_eq!(base % BASE_PAGE_SIZE, 0, "base is not page-aligned");
        assert_eq!(size % BASE_PAGE_SIZE, 0, "size is not page-aligned");
        Ok((PAddr::from(base.as_u64()), size))
    }

    pub(crate) fn map_generic(
        &mut self,
        vbase: VAddr,
        pregion: (PAddr, usize),
        rights: MapAction,
        pager: &mut crate::memory::tcache::TCache,
    ) -> Result<(), VSpaceError> {
        Ok(())
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        panic!("Drop for VSpace!");
    }
}
