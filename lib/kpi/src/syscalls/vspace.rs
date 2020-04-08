use crate::io::*;
use crate::*;

use crate::syscall;

use x86::bits64::paging::{PAddr, VAddr};

pub struct VSpace;

// TODO(api): should have individual API calls here (map, unmap, protect etc.)
impl VSpace {
    pub unsafe fn map(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::Map, base, bound)
    }

    pub unsafe fn unmap(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::Unmap, base, bound)
    }

    pub unsafe fn map_device(base: u64, bound: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::MapDevice, base, bound)
    }

    pub unsafe fn identify(base: u64) -> Result<(VAddr, PAddr), SystemCallError> {
        VSpace::vspace(VSpaceOperation::Identify, base, 0)
    }

    /// Manipulate the virtual address space.
    unsafe fn vspace(
        op: VSpaceOperation,
        base: u64,
        bound: u64,
    ) -> Result<(VAddr, PAddr), SystemCallError> {
        let (err, paddr, size) = syscall!(SystemCall::VSpace as u64, op as u64, base, bound, 3);

        log::trace!(
            "OP={:?} {:#x} -- {:#x} --> {:#x} -- {:#x}",
            op,
            base,
            base + bound,
            paddr,
            paddr + bound,
        );

        if err == 0 {
            debug_assert_eq!(
                bound, size,
                "VSpace Map should return mapped region size as 2nd argument"
            );
            Ok((VAddr::from(base), PAddr::from(paddr)))
        } else {
            Err(SystemCallError::from(err))
        }
    }
}
