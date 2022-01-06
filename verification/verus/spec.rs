
use crate::memory_types::*;
use crate::memory_types::Result::*;

use crate::pervasive::*;

#[spec]
pub struct AddressSpace { }

impl AddressSpace {
    /// Maps the given `frame` at `base` in the address space
    /// with the access rights defined by `action`.
    ///
    /// Will return an error if new mapping overlaps with
    /// something already mapped.
    #[spec] fn map_frame(self, base: VAddr, frame: Frame) -> Result<AddressSpace> {
        Ok(self)
    }

    // /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    // ///
    // /// # Returns
    // /// The range (vregion) that was adjusted if successfull.
    // ///fn adjust(&mut self, vaddr: VAddr) -> Result<(VAddr, usize), KError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    #[spec] fn resolve(self, vaddr: VAddr) -> Result<PAddr> {
        Ok(arbitrary())
    }

    /// Removes the frame from the address space that contains `vaddr`.
    ///
    /// # Returns
    /// The frame to the caller along with a `TlbFlushHandle` that may have to be
    /// invoked to flush the TLB.
    #[spec] fn unmap(self, vaddr: VAddr) -> Result<AddressSpace> {
        Ok(self)
    }
}
