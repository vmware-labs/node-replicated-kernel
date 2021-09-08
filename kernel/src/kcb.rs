// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KCB is the local kernel control that stores all core local state.

use alloc::string::String;
use alloc::sync::Arc;
use core::cell::{RefCell, RefMut};
use core::fmt::Debug;
use core::slice::from_raw_parts;

use arrayvec::ArrayVec;
use log::error;
use logos::Logos;
use node_replication::{Replica, ReplicaToken};
use slabmalloc::ZoneAllocator;

use crate::arch::kcb::init_kcb;
use crate::arch::memory::paddr_to_kernel_vaddr;
use crate::arch::MAX_NUMA_NODES;
use crate::error::KError;

use crate::arch::process::PROCESS_TABLE;
use crate::memory::emem::EmergencyAllocator;
use crate::memory::mcache::TCache;
use crate::memory::mcache::TCacheSp;
use crate::memory::{AllocatorStatistics, GlobalMemory, GrowBackend, PAddr, PhysicalPageProvider};
use crate::nr::KernelNode;
use crate::nrproc::NrProcess;
use crate::process::{Pid, Process, MAX_PROCESSES};

pub use crate::arch::kcb::{get_kcb, try_get_kcb};

pub trait MemManager: PhysicalPageProvider + AllocatorStatistics + GrowBackend {}

/// Definition to parse the kernel command-line arguments.
#[derive(Logos, Debug, PartialEq, Clone, Copy)]
enum CmdToken {
    /// Kernel binary name
    #[regex("./[a-zA-Z]+")]
    KernelBinary,

    /// Kernel log level directive
    #[token("log")]
    Log,

    /// Init binary (which is loaded by default)
    #[token("init")]
    InitBinary,

    /// Command line arguments to passed to init.
    #[token("initargs")]
    InitArgs,

    /// Command line arguments to passed to a (rump) application.
    #[token("appcmd")]
    AppArgs,

    #[regex("[a-zA-Z0-9\\._-]*")]
    Ident,

    /// Kernel log level
    #[token("=", priority = 22)]
    KVSeparator,

    #[regex(r#"'([^'\\]|\\t|\\u|\\n|[0-9a-zA-Z:.,_=]*|\\')*'"#)]
    LiteralString,

    /// Anything not properly encoded
    #[error]
    #[regex(r"[ ]+", logos::skip)]
    Error,
}

/// Arguments parsed from command line string passed
/// from the bootloader to the kernel.
#[derive(Copy, Clone, Debug)]
pub struct BootloaderArguments {
    pub log_filter: &'static str,
    pub init_binary: &'static str,
    pub init_args: &'static str,
    pub app_args: &'static str,
}

impl Default for BootloaderArguments {
    fn default() -> BootloaderArguments {
        BootloaderArguments {
            log_filter: "info",
            init_binary: "init",
            init_args: "",
            app_args: "",
        }
    }
}

impl BootloaderArguments {
    pub const fn new(
        log_filter: &'static str,
        init_binary: &'static str,
        init_args: &'static str,
        app_args: &'static str,
    ) -> Self {
        BootloaderArguments {
            log_filter,
            init_binary,
            init_args,
            app_args,
        }
    }

    /// Parse command line argument and initialize the logging infrastructure.
    ///
    /// Example: If args is './kernel log=trace' -> sets level to Level::Trace
    pub fn from_str(args: &'static str) -> BootloaderArguments {
        // The args argument will be a physical address slice that
        // goes away once we switch to a process address space
        // make sure we translate it into a kernel virtual address:
        let args_paddr = args.as_ptr();
        let args_kaddr = paddr_to_kernel_vaddr(PAddr::from(args_paddr as u64));
        // Safe: Depends on bootloader setting up identity mapping abobe `KERNEL_BASE`.
        let args_kslice = unsafe { from_raw_parts(args_kaddr.as_ptr(), args.len()) };
        let args = core::str::from_utf8(args_kslice).expect("Can't read args in kernel space?");

        let mut parsed_args: BootloaderArguments = Default::default();
        let mut lexer = CmdToken::lexer(args);
        let mut prev = CmdToken::Error;
        while let Some(token) = lexer.next() {
            let slice = lexer.slice();

            match token {
                CmdToken::KernelBinary => {
                    //assert_eq!(slice, "./kernel");
                }
                CmdToken::Log | CmdToken::InitBinary | CmdToken::InitArgs | CmdToken::AppArgs => {
                    prev = token;
                }
                CmdToken::Ident => match prev {
                    CmdToken::Log => {
                        parsed_args.log_filter = slice;
                        prev = CmdToken::Error;
                    }
                    CmdToken::InitBinary => {
                        parsed_args.init_binary = slice;
                        prev = CmdToken::Error;
                    }
                    CmdToken::InitArgs => {
                        parsed_args.init_args = slice;
                        prev = CmdToken::Error;
                    }
                    CmdToken::AppArgs => {
                        parsed_args.app_args = slice;
                        prev = CmdToken::Error;
                    }
                    _ => {
                        error!("Invalid cmd arguments: {} (skipped {})", args, slice);
                        continue;
                    }
                },
                CmdToken::KVSeparator => {
                    if prev != CmdToken::Log
                        && prev != CmdToken::InitBinary
                        && prev != CmdToken::InitArgs
                        && prev != CmdToken::AppArgs
                    {
                        error!("Malformed args (unexpected equal sign) in {}", args);
                        continue;
                    }
                }
                CmdToken::LiteralString => {
                    // We strip the quotes with 1..slice.len()-1
                    match prev {
                        CmdToken::Log => {
                            parsed_args.log_filter = &slice[1..slice.len() - 1];
                            prev = CmdToken::Error;
                        }
                        CmdToken::InitBinary => {
                            parsed_args.init_binary = &slice[1..slice.len() - 1];
                            prev = CmdToken::Error;
                        }
                        CmdToken::InitArgs => {
                            parsed_args.init_args = &slice[1..slice.len() - 1];
                            prev = CmdToken::Error;
                        }
                        CmdToken::AppArgs => {
                            parsed_args.app_args = &slice[1..slice.len() - 1];
                            prev = CmdToken::Error;
                        }
                        _ => {
                            error!("Invalid cmd arguments: {} (skipped {})", args, slice);
                            continue;
                        }
                    }
                }
                CmdToken::Error => {
                    error!("Ignored '{}' while parsing cmd args: {}", slice, args);
                    continue;
                }
            }
        }

        parsed_args
    }
}

/// State which allows to do memory management for a particular
/// NUMA node on a given core.
pub struct PhysicalMemoryArena {
    pub affinity: atopology::NodeId,

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the per-core page-allocator.
    pub pmanager: Option<RefCell<TCache>>,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,
}

impl PhysicalMemoryArena {
    fn new(node: atopology::NodeId, global_memory: &'static GlobalMemory) -> Self {
        PhysicalMemoryArena {
            affinity: node,
            gmanager: Some(global_memory),
            pmanager: Some(RefCell::new(TCache::new(node))),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }

    const fn uninit_with_node(node: atopology::NodeId) -> Self {
        PhysicalMemoryArena {
            affinity: node,
            gmanager: None,
            pmanager: None,
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }
}

/// The Kernel Control Block for a given core.
/// It contains all core-local state of the kernel.
pub struct Kcb<A>
where
    A: ArchSpecificKcb,
    <<A as ArchSpecificKcb>::Process as crate::process::Process>::E: Debug + 'static,
{
    /// Architecture specific members of the KCB.
    pub arch: A,

    /// Are we in panic mode? Hopfully not.
    ///
    /// # See also
    /// - `panic.rs`
    pub in_panic_mode: bool,

    pub cmdline: BootloaderArguments,

    /// A pointer to the memory location of the kernel (ELF binary).
    kernel_binary: &'static [u8],

    /// A handle to the early page-allocator.
    pub emanager: RefCell<TCacheSp>,

    /// A handle to a bump-style emergency Allocator.
    pub ezone_allocator: RefCell<EmergencyAllocator>,

    /// Related meta-data to manage physical memory for a given NUMA node.
    pub physical_memory: PhysicalMemoryArena,

    /// Related meta-data to manage persistent memory for a given NUMA node.
    pub pmem_memory: PhysicalMemoryArena,

    /// Which NUMA node this KCB / core belongs to
    ///
    /// TODO(redundant): use kcb.arch.node_id
    pub node: atopology::NodeId,

    pub print_buffer: Option<String>,

    /// Contains a bunch of memory arenas, can be one for every NUMA node
    /// but we intialize it lazily upon calling `set_allocation_affinity`.
    pub memory_arenas: [Option<PhysicalMemoryArena>; crate::arch::MAX_NUMA_NODES],

    /// Contains a bunch of pmem arenas, can be one for every NUMA node
    /// but we intialize it lazily upon calling `set_allocation_affinity`.
    pub pmem_arenas: [Option<PhysicalMemoryArena>; crate::arch::MAX_NUMA_NODES],

    /// A handle to the node-local kernel replica.
    pub replica: Option<(Arc<Replica<'static, KernelNode>>, ReplicaToken)>,

    /// Measures cycles spent in TLB shootdown handler for responder.
    pub tlb_time: u64,

    /// Tokens to access process replicas
    pub process_token: ArrayVec<ReplicaToken, { MAX_PROCESSES }>,
}

impl<A: ArchSpecificKcb> Kcb<A> {
    pub const fn new(
        kernel_binary: &'static [u8],
        cmdline: BootloaderArguments,
        emanager: TCacheSp,
        arch: A,
        node: atopology::NodeId,
    ) -> Kcb<A> {
        const DEFAULT_PHYSICAL_MEMORY_ARENA: Option<PhysicalMemoryArena> = None;

        Kcb {
            arch,
            cmdline,
            in_panic_mode: false,
            kernel_binary,
            emanager: RefCell::new(emanager),
            ezone_allocator: RefCell::new(EmergencyAllocator::empty()),
            node,
            memory_arenas: [DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES],
            pmem_arenas: [DEFAULT_PHYSICAL_MEMORY_ARENA; MAX_NUMA_NODES],
            // Can't initialize these yet, we need basic Kcb first for
            // memory allocations (emanager):
            physical_memory: PhysicalMemoryArena::uninit_with_node(node),
            pmem_memory: PhysicalMemoryArena::uninit_with_node(node),
            print_buffer: None,
            replica: None,
            tlb_time: 0,
            process_token: ArrayVec::new_const(),
        }
    }

    pub fn setup_node_replication(
        &mut self,
        replica: Arc<Replica<'static, KernelNode>>,
        idx_token: ReplicaToken,
    ) {
        self.replica = Some((replica, idx_token));
    }

    pub fn register_with_process_replicas(&mut self) {
        let node = self.arch.node();
        debug_assert!(PROCESS_TABLE.len() > node, "Invalid Node ID");

        for pid in 0..MAX_PROCESSES {
            debug_assert!(PROCESS_TABLE[node].len() > pid, "Invalid PID");

            let token = PROCESS_TABLE[node][pid].register();
            self.process_token
                .push(token.expect("Need to be able to register"));
        }
    }

    pub fn set_panic_mode(&mut self) {
        self.in_panic_mode = true;
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub fn install(&'static mut self) {
        self.arch.install();

        // Reloading gdt means we lost the content in `gs` so we
        // also set the kcb again using `wrgsbase`:
        init_kcb(self);
    }

    pub fn set_global_memory(&mut self, gm: &'static GlobalMemory) {
        self.physical_memory.gmanager = Some(gm);
    }

    pub fn set_global_pmem(&mut self, gm: &'static GlobalMemory) {
        self.pmem_memory.gmanager = Some(gm);
    }

    pub fn set_allocation_affinity(&mut self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.physical_memory.affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }

        if node < self.memory_arenas.len() && node < atopology::MACHINE_TOPOLOGY.num_nodes() {
            let gmanager = self
                .physical_memory
                .gmanager
                .ok_or(KError::GlobalMemoryNotSet)?;

            if self.memory_arenas[node].is_none() {
                self.memory_arenas[node] = Some(PhysicalMemoryArena::new(node, gmanager));
            }
            debug_assert!(self.memory_arenas[node].is_some());
            let mut arena = self.memory_arenas[node].take().unwrap();
            debug_assert_eq!(arena.affinity, node);

            core::mem::swap(&mut arena, &mut self.physical_memory);
            self.memory_arenas[arena.affinity as usize].replace(arena);

            Ok(())
        } else {
            Err(KError::InvalidAffinityId)
        }
    }

    pub fn set_pmem_affinity(&mut self, node: atopology::NodeId) -> Result<(), KError> {
        if node == self.pmem_memory.affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }

        if node < self.pmem_arenas.len() && node < atopology::MACHINE_TOPOLOGY.num_nodes() {
            let gmanager = self
                .pmem_memory
                .gmanager
                .ok_or(KError::GlobalMemoryNotSet)?;

            if self.pmem_arenas[node].is_none() {
                self.pmem_arenas[node] = Some(PhysicalMemoryArena::new(node, gmanager));
            }
            debug_assert!(self.pmem_arenas[node].is_some());
            let mut arena = self.pmem_arenas[node].take().unwrap();
            debug_assert_eq!(arena.affinity, node);

            core::mem::swap(&mut arena, &mut self.pmem_memory);
            self.pmem_arenas[arena.affinity as usize].replace(arena);

            Ok(())
        } else {
            Err(KError::InvalidAffinityId)
        }
    }

    pub fn set_physical_memory_manager(&mut self, pmanager: TCache) {
        self.physical_memory.pmanager = Some(RefCell::new(pmanager));
    }

    pub fn set_pmem_manager(&mut self, pmanager: TCache) {
        self.pmem_memory.pmanager = Some(RefCell::new(pmanager));
    }

    pub fn enable_print_buffering(&mut self, buffer: String) {
        self.print_buffer = Some(buffer);
    }

    /// Get a reference to the early memory manager.
    pub fn emanager(&self) -> RefMut<TCacheSp> {
        self.emanager.borrow_mut()
    }

    /// Get a reference to the early memory manager.
    fn try_borrow_emanager(&self) -> Result<RefMut<dyn MemManager>, core::cell::BorrowMutError> {
        self.emanager
            .try_borrow_mut()
            .map(|rmt| RefMut::map(rmt, |t| t as &mut dyn MemManager))
    }

    pub fn ezone_allocator(
        &self,
    ) -> Result<RefMut<impl slabmalloc::Allocator<'static>>, core::cell::BorrowMutError> {
        self.ezone_allocator.try_borrow_mut()
    }

    pub fn zone_allocator(
        &self,
    ) -> Result<RefMut<impl slabmalloc::Allocator<'static>>, core::cell::BorrowMutError> {
        self.physical_memory.zone_allocator.try_borrow_mut()
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<dyn MemManager> {
        if core::intrinsics::unlikely(self.in_panic_mode) {
            return self.emanager();
        }

        self.physical_memory
            .pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    pub fn try_mem_manager(&self) -> Result<RefMut<dyn MemManager>, core::cell::BorrowMutError> {
        if core::intrinsics::unlikely(self.in_panic_mode) {
            return Ok(self.emanager());
        }

        self.physical_memory.pmanager.as_ref().map_or_else(
            || self.try_borrow_emanager(),
            |pmem| {
                pmem.try_borrow_mut()
                    .map(|rmt| RefMut::map(rmt, |t| t as &mut dyn MemManager))
            },
        )
    }

    pub fn pmem_manager(&self) -> RefMut<dyn MemManager> {
        self.pmem_memory
            .pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }

    pub fn current_pid(&self) -> Result<Pid, KError> {
        self.arch.current_pid()
    }
}

pub trait ArchSpecificKcb {
    type Process: Process + Sync;

    fn node(&self) -> usize;
    fn hwthread_id(&self) -> usize;
    fn install(&mut self);
    fn current_pid(&self) -> Result<Pid, KError>;

    #[allow(clippy::type_complexity)] // fix this once `associated_type_defaults` works
    fn process_table(
        &self,
    ) -> &'static ArrayVec<
        ArrayVec<Arc<Replica<'static, NrProcess<Self::Process>>>, MAX_PROCESSES>,
        MAX_NUMA_NODES,
    >;
}

#[cfg(test)]
mod test {
    use super::BootloaderArguments;

    #[test]
    fn parse_args_empty() {
        let ba = BootloaderArguments::from_str("");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_nrk() {
        let ba = BootloaderArguments::from_str("./nrk");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_basic() {
        let ba = BootloaderArguments::from_str("./kernel");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_log() {
        let ba = BootloaderArguments::from_str("./kernel log=error");
        assert_eq!(ba.log_filter, "error");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_init() {
        let ba = BootloaderArguments::from_str("./kernel init=file log=trace");
        assert_eq!(ba.log_filter, "trace");
        assert_eq!(ba.init_binary, "file");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_initargs() {
        let ba = BootloaderArguments::from_str("./kernel initargs=0");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "0");
    }

    #[test]
    fn parse_args_leveldb() {
        let args = "./kernel log=warn init=dbbench.bin initargs=3 appcmd='--threads=1 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535'";

        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "warn");
        assert_eq!(ba.init_binary, "dbbench.bin");
        assert_eq!(ba.init_args, "3");
        assert_eq!(ba.app_args, "--threads=1 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535");
    }

    #[test]
    fn parse_args_fxmark() {
        let args = "log=debug initargs=1X1XmixX0";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "1X1XmixX0");
    }

    #[test]
    fn parse_args_empty_literal_quotes() {
        let args = "./kernel initargs='\"\"' log=debug";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "\"\"");
    }

    #[test]
    fn parse_args_empty_literal() {
        let args = "./kernel initargs='' log=debug";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid() {
        let args = "./kernel initg='asdf' log=debug";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid2() {
        let args = "./sadf init='asdf' log=debug";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid3() {
        let args = "./kernel init=---  as-s- log=debug";
        let ba = BootloaderArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }
}
