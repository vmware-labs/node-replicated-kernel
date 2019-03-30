use super::memory::VAddr;

pub struct VSpace {}

impl VSpace {
    pub fn map_identity(&mut self, base: VAddr, end: VAddr) {
        unreachable!("map_identity 0x{:x} -- 0x{:x}", base, end);
    }
}
