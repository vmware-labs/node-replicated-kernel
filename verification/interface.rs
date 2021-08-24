/// Generic address space functionality.
pub trait AddressSpace {
    /// Maps the given `frame` at `base` in the address space
    /// with the access rights defined by `action`.
    ///
    /// Will return an error if new mapping overlaps with
    /// something already mapped.
    fn map_frame(&mut self, base: VAddr, frame: Frame) -> Result<(), KError>;

    /// Changes the mapping permissions of the region containing `vaddr` to `rights`.
    ///
    /// # Returns
    /// The range (vregion) that was adjusted if successfull.
    ///fn adjust(&mut self, vaddr: VAddr) -> Result<(VAddr, usize), KError>;

    /// Given a virtual address `vaddr` it returns the corresponding `PAddr`
    /// and access rights or an error in case no mapping is found.
    fn resolve(&self, vaddr: VAddr) -> Result<(PAddr), KError>;

    /// Removes the frame from the address space that contains `vaddr`.
    ///
    /// # Returns
    /// The frame to the caller along with a `TlbFlushHandle` that may have to be
    /// invoked to flush the TLB.
    fn unmap(&mut self, vaddr: VAddr) -> Result<TlbFlushHandle, KError>;
}
