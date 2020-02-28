//! KCB is the local kernel control that stores all core local state.

use core::cell::{RefCell, RefMut};

use logos::Logos;
use slabmalloc::ZoneAllocator;

use crate::arch::kcb::init_kcb;
use crate::memory::{tcache::TCache, GlobalMemory};

pub use crate::arch::kcb::{get_kcb, try_get_kcb};

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

    /// Anything not properly encoded
    #[error]
    Error,

    /// Test binary.
    #[token = "testbinary="]
    TestBinary,

    /// Log token.
    #[token = "log="]
    Log,

    #[regex = "[a-zA-Z]+\\.bin"]
    File,

    /// Regular expressions for parsing log-filter or file-path names.
    ///
    /// Example: 'bespin::memory=debug,topology::acpi=debug'
    /// TODO(improve): the regular expression "(,?([a-zA-Z]+(::)?[a-zA-Z]+)=?[a-zA-Z]+)+"
    #[regex = "[a-zA-Z:,=]+"]
    Value,
}

#[derive(Copy, Clone)]
pub struct CommandLineArgs {
    pub log_filter: &'static str,
    pub test_binary: &'static str,
}

impl CommandLineArgs {
    /// Parse command line argument and initialize the logging infrastructure.
    ///
    /// Example: If args is './kernel log=trace' -> sets level to Level::Trace
    pub fn from_str(args: &'static str) -> CommandLineArgs {
        let mut parsed_args: CommandLineArgs = Default::default();
        let mut lexer = CmdToken::lexer(args);

        loop {
            lexer.advance();
            match (lexer.token, lexer.slice()) {
                (CmdToken::Binary, bin) => assert_eq!(bin, "./kernel"),
                (CmdToken::Log, _) => {
                    lexer.advance();
                    parsed_args.log_filter = match (lexer.token, lexer.slice()) {
                        // matches for simple things like `info`, `error` etc.
                        (CmdToken::Value, text) => text,
                        (_t, _v) => "debug",
                    };
                }
                (CmdToken::TestBinary, _) => {
                    lexer.advance();
                    parsed_args.test_binary = match (lexer.token, lexer.slice()) {
                        (CmdToken::File, file_name) => file_name,
                        (_t, _v) => "init",
                    };
                }
                (CmdToken::End, _) => break,
                (_, _) => continue,
            };
        }

        parsed_args
    }
}

impl Default for CommandLineArgs {
    fn default() -> CommandLineArgs {
        CommandLineArgs {
            log_filter: "info",
            test_binary: "init",
        }
    }
}

/// The Kernel Control Block for a given core.
/// It contains all core-local state of the kernel.
pub struct Kcb<A> {
    /// Architecture specific members of the KCB.
    pub arch: A,

    pub cmdline: CommandLineArgs,

    /// A pointer to the memory location of the kernel (ELF binary).
    kernel_binary: &'static [u8],

    /// A handle to the global memory manager.
    pub gmanager: Option<&'static GlobalMemory>,

    /// A handle to the early memory manager.
    pub emanager: RefCell<TCache>,

    /// A handle to the per-core page-allocator.
    pub pmanager: Option<RefCell<TCache>>,

    /// A handle to the per-core ZoneAllocator.
    pub zone_allocator: RefCell<ZoneAllocator<'static>>,

    /// Which NUMA node this KCB / core belongs to
    pub node: topology::NodeId,

    /// Allocation affinity (which node we allocate from,
    /// this is a hack remove once custom allocators land).
    allocation_affinity: topology::NodeId,
}

impl<A: ArchSpecificKcb> Kcb<A> {
    pub fn new(
        kernel_binary: &'static [u8],
        cmdline: CommandLineArgs,
        emanager: TCache,
        arch: A,
        node: topology::NodeId,
    ) -> Kcb<A> {
        Kcb {
            arch,
            cmdline,
            kernel_binary,
            emanager: RefCell::new(emanager),
            zone_allocator: RefCell::new(ZoneAllocator::new()),
            node,
            allocation_affinity: 0,
            // Can't initialize these yet, needs basic Kcb first for
            // memory allocations:
            gmanager: None,
            pmanager: None,
        }
    }

    /// Ties this KCB to the local CPU by setting the KCB's GDT and IDT.
    pub fn install(&'static mut self) {
        self.arch.install();

        // Reloading gdt means we lost the content in `gs` so we
        // also set the kcb again using `wrgsbase`:
        init_kcb(self);
    }

    pub fn set_global_memory(&mut self, gm: &'static GlobalMemory) {
        self.gmanager = Some(gm);
    }

    pub fn set_allocation_affinity(&mut self, node: topology::NodeId) {
        self.allocation_affinity = node;
    }

    pub fn set_physical_memory_manager(&mut self, pmanager: TCache) {
        self.pmanager = Some(RefCell::new(pmanager));
    }

    /// Get a reference to the early memory manager.
    pub fn emanager(&self) -> RefMut<TCache> {
        self.emanager.borrow_mut()
    }

    /// Returns a reference to the core-local physical memory manager if set,
    /// otherwise returns the early physical memory manager.
    pub fn mem_manager(&self) -> RefMut<TCache> {
        self.pmanager
            .as_ref()
            .map_or(self.emanager(), |pmem| pmem.borrow_mut())
    }

    pub fn try_mem_manager(&self) -> Result<RefMut<TCache>, core::cell::BorrowMutError> {
        self.pmanager
            .as_ref()
            .map_or(self.emanager.try_borrow_mut(), |pmem| pmem.try_borrow_mut())
    }

    pub fn kernel_binary(&self) -> &'static [u8] {
        self.kernel_binary
    }
}

pub trait ArchSpecificKcb {
    fn install(&mut self);
}
