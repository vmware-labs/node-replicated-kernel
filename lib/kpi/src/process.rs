// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryInto;

use serde::{Deserialize, Serialize};
use x86::bits64::paging::PML4_SLOT_SIZE;

/// Max number of cores supported by the process allocator.
pub const MAX_CORES: usize = 96;

/// Offset in address-space for ELF binary relocation.
pub const ELF_OFFSET: usize = 0x20_0000_0000;

/// Memory region space for shared executor region is allocated.
pub const EXECUTOR_OFFSET: usize = 0x21_0000_0000;

/// Start of Heap memory
pub const HEAP_START: usize = 0x30_0000_0000;

/// Address space region for each core in the heap.
pub const HEAP_PER_CORE_REGION: usize = 0x2_0000_0000;

/// End of Heap memory.
pub const HEAP_END: usize = HEAP_START + ((MAX_CORES + 1) * HEAP_PER_CORE_REGION);

// Make sure that all our process regions are in the first PML4 slot. This isn't
// really necessary for anything except benchmarking: it helps for scalability
// benchmarks if we know that all other slots are "empty" and we don't
// accidentially try to map somewhere where there are already mappings...
static_assertions::const_assert!(HEAP_END <= 2 * PML4_SLOT_SIZE);
static_assertions::const_assert!(EXECUTOR_OFFSET <= PML4_SLOT_SIZE);
static_assertions::const_assert!(ELF_OFFSET <= PML4_SLOT_SIZE);

pub type FrameId = usize;

#[derive(Debug)]
pub struct CoreToken(usize);

impl CoreToken {
    #[allow(unused)]
    pub(crate) fn from(ret: u64) -> Self {
        CoreToken(ret.try_into().unwrap())
    }
}

// TODO: still use serde instead of abomonation because abomonation doesn't
// know how to handle 'static string.
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
    /// Command line arguments
    pub cmdline: &'static str,
    /// App specific command line argument, for example: benchmarks, reads,
    /// value_size for leveldb (passed to the rump init function).
    pub app_cmdline: &'static str,
}

#[cfg(test)]
#[test]
fn serialize() {
    use alloc::vec::Vec;

    let _r = env_logger::try_init();
    let point = ProcessInfo {
        has_tls: true,
        tls_data: 0xdead,
        tls_data_len: 4,
        tls_len_total: 8,
        alignment: 3,
        cmdline: "test",
        app_cmdline: "app_cmdline",
    };

    let serialized: &'static [u8] = Vec::leak(serde_cbor::to_vec(&point).unwrap());
    let deserialized: ProcessInfo = serde_cbor::from_slice(&serialized).unwrap();
    log::info!("serialized.len = {}", serialized.len());
    log::info!("deserialized = {:?}", deserialized);
}
