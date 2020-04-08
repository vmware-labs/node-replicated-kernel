use core::convert::TryInto;
use serde::{Deserialize, Serialize};

pub struct CoreToken(usize);

impl CoreToken {
    pub(crate) fn from(ret: u64) -> Self {
        CoreToken(ret.try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct ProcessInfo {
    pub has_tls: bool,
    /// Start of initial TLS data section in the address space.
    pub tls_data: u64,
    /// Length of initial TLS data section in the address space.
    pub tls_data_len: u64,
    /// Required size of the TLS .bss section
    pub tls_len_total: u64,
    /// Required alignment
    pub alignment: u64,
}

#[cfg(test)]
#[test]
fn serialize() {
    let _r = env_logger::try_init();
    let point = ProcessInfo {
        has_tls: true,
        tls_data: 0xdead,
        tls_data_len: 4,
        tls_len_total: 8,
        alignment: 3,
    };

    let serialized = serde_cbor::to_vec(&point).unwrap();
    let deserialized: ProcessInfo = serde_cbor::from_slice(&serialized).unwrap();
    log::info!("serialized.len = {}", serialized.len());
    log::info!("deserialized = {:?}", deserialized);
}
