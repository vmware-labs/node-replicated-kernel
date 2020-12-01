//! KCB is the local kernel control that stores all core local state.

use alloc::string::String;
use core::cell::{RefCell, RefMut};
use core::convert::TryInto;
use core::slice::from_raw_parts;

use logos::Logos;
use slabmalloc::ZoneAllocator;

use crate::arch::kcb::init_kcb;
use crate::arch::memory::paddr_to_kernel_vaddr;
use crate::error::KError;
use crate::fs::{FileSystem, MemFS};
use crate::memory::tcache_sp::TCacheSp;
use crate::memory::{
    emem::EmergencyAllocator, tcache::TCache, AllocatorStatistics, GlobalMemory, GrowBackend,
    PAddr, PhysicalPageProvider,
};

pub use crate::arch::kcb::{get_kcb, try_get_kcb};

pub trait MemManager: PhysicalPageProvider + AllocatorStatistics + GrowBackend {}

/// Definition to parse the kernel command-line arguments.
#[derive(Logos, Debug, PartialEq, Clone, Copy)]
enum CmdToken {
    /// Logos requires that we define two default variants,
    /// one for end of input source,
    #[end]
    End,

    /// Kernel binary name
    #[regex = "./[a-zA-Z]+"]
    Binary,

    /// Argument separator (1 space)
    #[token = " "]
    ArgSeparator,

    /// Test binary.
    #[token = "testbinary="]
    TestBinary,

    /// Test command line argument.
    #[token = "testcmd="]
    TestCmd,

    /// Log token.
    #[token = "log="]
    Log,

    #[regex = "(trace|debug|info|warn|error)"]
    LogLevelSimple,

    /// Regular expressions for parsing log-filter or file-path names.
    ///
    /// Example: 'bespin::memory=debug,topology::acpi=debug'
    /// TODO(improve): the regular expression "(,?([a-zA-Z]+(::)?[a-zA-Z]+)=?[a-zA-Z]+)+"
    #[regex = "[a-zA-Z:,=]+"]
    LogComplex,

    /// A file that we want to execute
    #[regex = "[a-zA-Z]+(\\.bin)?"]
    File,

    /// A file that we want to execute
    #[regex = "[0-9a-zA-Z]+"]
    CmdLine,

    /// Anything not properly encoded
    #[error]
    Error,
}

/// Arguments parsed from command line string passed
/// from the bootloader to the kernel.
#[derive(Copy, Clone, Debug)]
pub struct BootloaderArguments {
    pub log_filter: &'static str,
    pub test_binary: &'static str,
    pub test_cmdline: &'static str,
}

impl BootloaderArguments {
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

        loop {
            lexer.advance();
            match (lexer.token, lexer.slice()) {
                (CmdToken::Binary, bin) => assert_eq!(bin, "./kernel"),
                (CmdToken::Log, _) => {
                    lexer.advance();
                    parsed_args.log_filter = match (lexer.token, lexer.slice()) {
                        // matches for simple things like `info`, `error` etc.
                        (CmdToken::LogComplex, text) => text,
                        (CmdToken::LogLevelSimple, level) => level,
                        (key, v) => {
                            unreachable!("Malformed command-line parsing log: {:?} -> {:?}", key, v)
                        }
                    };
                }
                (CmdToken::TestBinary, _) => {
                    lexer.advance();
                    parsed_args.test_binary = match (lexer.token, lexer.slice()) {
                        (CmdToken::File, file_name) => file_name,
                        (key, v) => unreachable!(
                            "Malformed command-line parsing testbinary: {:?} -> {:?}",
                            key, v
                        ),
                    };
                }
                (CmdToken::TestCmd, _) => {
                    lexer.advance();
                    parsed_args.test_cmdline = match (lexer.token, lexer.slice()) {
                        (CmdToken::CmdLine, test_cmdline) => test_cmdline,
                        (key, v) => unreachable!(
                            "Malformed command-line parsing testbinary: {:?} -> {:?}",
                            key, v
                        ),
                    };
                }
                (CmdToken::End, _) => break,
                (_, _) => continue,
            };
        }

        parsed_args
    }
}

impl Default for BootloaderArguments {
    fn default() -> BootloaderArguments {
        BootloaderArguments {
            log_filter: "info",
            test_binary: "init",
            test_cmdline: "init",
        }
    }
}

/// State which allows to do memory management for a particular
/// NUMA node on a given core.
pub struct PhysicalMemoryArena {
    pub affinity: topology::NodeId,

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the per-core page-allocator.
    pub pmanager: Option<RefCell<TCache>>,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,
}

impl PhysicalMemoryArena {
    fn new(node: topology::NodeId, global_memory: &'static GlobalMemory) -> Self {
        PhysicalMemoryArena {
            affinity: node,
            gmanager: Some(global_memory),
            pmanager: Some(RefCell::new(TCache::new(
                topology::MACHINE_TOPOLOGY.current_thread().id,
                node,
            ))),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
        }
    }

    fn uninit_with_node(node: topology::NodeId) -> Self {
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
pub struct Kcb<A> {
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

    /// Which NUMA node this KCB / core belongs to
    pub node: topology::NodeId,

    /// A dummy in-memory file system to test the memory
    /// system and file system operations with NR.
    pub memfs: Option<MemFS>,

    pub print_buffer: Option<String>,

    /// Contains a bunch of memory arenas, can be one for every NUMA node
    /// but we intialize it lazily upon calling `set_allocation_affinity`.
    pub memory_arenas: [Option<PhysicalMemoryArena>; crate::arch::MAX_NUMA_NODES],
}

impl<A: ArchSpecificKcb> Kcb<A> {
    pub fn new(
        kernel_binary: &'static [u8],
        cmdline: BootloaderArguments,
        emanager: TCacheSp,
        arch: A,
        node: topology::NodeId,
    ) -> Kcb<A> {
        Kcb {
            arch,
            cmdline,
            in_panic_mode: false,
            kernel_binary,
            emanager: RefCell::new(emanager),
            ezone_allocator: RefCell::new(EmergencyAllocator::default()),
            node,
            memory_arenas: [None; crate::arch::MAX_NUMA_NODES],
            // Can't initialize these yet, we need basic Kcb first for
            // memory allocations (emanager):
            physical_memory: PhysicalMemoryArena::uninit_with_node(node),
            memfs: None,
            print_buffer: None,
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

    pub fn set_allocation_affinity(&mut self, node: topology::NodeId) -> Result<(), KError> {
        let node_idx: usize = node.try_into().unwrap();
        if node == self.physical_memory.affinity {
            // Allocation affinity is already set to correct NUMA node
            return Ok(());
        }

        if node_idx < self.memory_arenas.len() && node_idx < topology::MACHINE_TOPOLOGY.num_nodes()
        {
            let gmanager = self
                .physical_memory
                .gmanager
                .ok_or(KError::GlobalMemoryNotSet)?;

            if self.memory_arenas[node_idx].is_none() {
                self.memory_arenas[node_idx] = Some(PhysicalMemoryArena::new(node, gmanager));
            }
            debug_assert!(self.memory_arenas[node_idx].is_some());
            let mut arena = self.memory_arenas[node_idx].take().unwrap();
            debug_assert_eq!(arena.affinity as usize, node_idx);

            core::mem::swap(&mut arena, &mut self.physical_memory);
            self.memory_arenas[arena.affinity as usize].replace(arena);

            Ok(())
        } else {
            Err(KError::InvalidAffinityId)
        }
    }

    pub fn set_physical_memory_manager(&mut self, pmanager: TCache) {
        self.physical_memory.pmanager = Some(RefCell::new(pmanager));
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

        self.physical_memory
            .pmanager
            .as_ref()
            .map_or(self.try_borrow_emanager(), |pmem| {
                pmem.try_borrow_mut()
                    .map(|rmt| RefMut::map(rmt, |t| t as &mut dyn MemManager))
            })
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }

    /// Initialized the dummy file-system to measure the write() system call
    /// overhead. Accessing the memfs in multiple threads is unsafe.
    pub fn init_memfs(&mut self) {
        self.memfs = Some(Default::default());
        let _result = self.memfs.as_mut().unwrap().create("bespin", 0x007);
    }
}

pub trait ArchSpecificKcb {
    fn install(&mut self);
}
