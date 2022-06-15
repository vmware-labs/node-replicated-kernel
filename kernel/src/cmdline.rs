// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kernel command line parser.

use core::fmt::Debug;
use core::slice::from_raw_parts;

use log::error;
use logos::Logos;

use crate::arch::memory::paddr_to_kernel_vaddr;
use crate::memory::PAddr;

/// Definition to parse the kernel command-line arguments.
#[derive(Logos, Debug, PartialEq, Clone, Copy)]
enum CmdToken {
    /// Kernel binary name
    #[regex("./[a-zA-Z]+")]
    KernelBinary,

    /// Run kernel test
    #[token("test")]
    Test,

    /// Run kernel test
    #[token("log")]
    Log,

    #[token("mode")]
    Mode,

    #[token("transport")]
    Transport,

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

/// Mode the kernel operates in (for rackscale execution).
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Mode {
    /// Normal mode.
    Native,
    /// Controller mode (control many kernels).
    Controller,
    /// Worker mode (talk to a controller for decisions).
    Client,
}

impl From<&str> for Mode {
    fn from(s: &str) -> Self {
        match s {
            "native" => Mode::Native,
            "controller" => Mode::Controller,
            "client" => Mode::Client,
            _ => Mode::Native,
        }
    }
}

/// Transport used for RPCs (for rackscale execution).
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Transport {
    /// Shared memory transport.
    Shmem,
    /// Smoltcp-based TCP transport.
    Smoltcp,
}

impl From<&str> for Transport {
    fn from(s: &str) -> Self {
        match s {
            "smoltcp" => Transport::Smoltcp,
            "shmem" => Transport::Shmem,
            _ => Transport::Shmem,
        }
    }
}

/// Arguments parsed from command line string passed from the bootloader to the
/// kernel.
#[derive(Copy, Clone, Debug)]
pub(crate) struct CommandLineArguments {
    pub log_filter: &'static str,
    pub init_binary: &'static str,
    pub init_args: &'static str,
    pub app_args: &'static str,
    pub test: Option<&'static str>,
    pub mode: Mode,
    pub transport: Transport,
}
// If you move or rename `CommandLineArguments`, you may also need to update the `s02_gdb` test.
static_assertions::assert_type_eq_all!(CommandLineArguments, crate::cmdline::CommandLineArguments);

impl Default for CommandLineArguments {
    fn default() -> Self {
        Self {
            log_filter: "info",
            init_binary: "init",
            init_args: "",
            app_args: "",
            test: None,
            mode: Mode::Native,
            transport: Transport::Shmem,
        }
    }
}

impl CommandLineArguments {
    /// Parse command line argument and initialize the logging infrastructure.
    ///
    /// Example: If args is './kernel log=trace' -> sets level to Level::Trace
    pub(crate) fn from_str(args: &'static str) -> Self {
        // The args argument will be a physical address slice that
        // goes away once we switch to a process address space
        // make sure we translate it into a kernel virtual address:
        let args_paddr = args.as_ptr();
        let args_kaddr = paddr_to_kernel_vaddr(PAddr::from(args_paddr as u64));
        // Safe: Depends on bootloader setting up identity mapping abobe `KERNEL_BASE`.
        let args_kslice = unsafe { from_raw_parts(args_kaddr.as_ptr(), args.len()) };
        let args = core::str::from_utf8(args_kslice).expect("Can't read args in kernel space?");

        let mut parsed_args: CommandLineArguments = Default::default();
        let mut lexer = CmdToken::lexer(args);
        let mut prev = CmdToken::Error;
        while let Some(token) = lexer.next() {
            let slice = lexer.slice();

            match token {
                CmdToken::KernelBinary => {
                    //assert_eq!(slice, "./kernel");
                }
                CmdToken::Log
                | CmdToken::Mode
                | CmdToken::Transport
                | CmdToken::Test
                | CmdToken::InitBinary
                | CmdToken::InitArgs
                | CmdToken::AppArgs => {
                    prev = token;
                }
                CmdToken::Ident => match prev {
                    CmdToken::Log => {
                        parsed_args.log_filter = slice;
                        prev = CmdToken::Error;
                    }
                    CmdToken::Mode => {
                        parsed_args.mode = slice.into();
                        prev = CmdToken::Error;
                    }
                    CmdToken::Transport => {
                        parsed_args.transport = slice.into();
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
                    CmdToken::Test => {
                        parsed_args.test = Some(slice);
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
                        && prev != CmdToken::Test
                    {
                        error!("Malformed args (unexpected equal sign) in {}", args);
                        continue;
                    }
                }
                CmdToken::LiteralString => {
                    // We strip the quotes with 1..slice.len()-1
                    let slice_no_quote = &slice[1..slice.len() - 1];
                    match prev {
                        CmdToken::Log => {
                            parsed_args.log_filter = slice_no_quote;
                            prev = CmdToken::Error;
                        }
                        CmdToken::InitBinary => {
                            parsed_args.init_binary = slice_no_quote;
                            prev = CmdToken::Error;
                        }
                        CmdToken::InitArgs => {
                            parsed_args.init_args = slice_no_quote;
                            prev = CmdToken::Error;
                        }
                        CmdToken::AppArgs => {
                            parsed_args.app_args = slice_no_quote;
                            prev = CmdToken::Error;
                        }
                        CmdToken::Test => {
                            parsed_args.test = Some(slice_no_quote);
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

#[cfg(test)]
mod test {
    use super::CommandLineArguments;

    #[test]
    fn parse_args_empty() {
        let ba = CommandLineArguments::from_str("");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_nrk() {
        let ba = CommandLineArguments::from_str("./nrk");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_basic() {
        let ba = CommandLineArguments::from_str("./kernel");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_log() {
        let ba = CommandLineArguments::from_str("./kernel log=error");
        assert_eq!(ba.log_filter, "error");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_init() {
        let ba = CommandLineArguments::from_str("./kernel init=file log=trace");
        assert_eq!(ba.log_filter, "trace");
        assert_eq!(ba.init_binary, "file");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_initargs() {
        let ba = CommandLineArguments::from_str("./kernel initargs=0");
        assert_eq!(ba.log_filter, "info");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "0");
    }

    #[test]
    fn parse_args_leveldb() {
        let args = "./kernel log=warn init=dbbench.bin initargs=3 appcmd='--threads=1 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535'";

        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "warn");
        assert_eq!(ba.init_binary, "dbbench.bin");
        assert_eq!(ba.init_args, "3");
        assert_eq!(ba.app_args, "--threads=1 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535");
    }

    #[test]
    fn parse_args_fxmark() {
        let args = "log=debug initargs=1X1XmixX0";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_binary, "init");
        assert_eq!(ba.init_args, "1X1XmixX0");
    }

    #[test]
    fn parse_args_empty_literal_quotes() {
        let args = "./kernel initargs='\"\"' log=debug";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "\"\"");
    }

    #[test]
    fn parse_args_empty_literal() {
        let args = "./kernel initargs='' log=debug";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid() {
        let args = "./kernel initg='asdf' log=debug";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid2() {
        let args = "./sadf init='asdf' log=debug";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_args_invalid3() {
        let args = "./kernel init=---  as-s- log=debug";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "debug");
        assert_eq!(ba.init_args, "");
    }

    #[test]
    fn parse_log_level_complex() {
        let args = "./kernel log='gdbstub=trace,nrk::arch::gdb=trace'";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.log_filter, "gdbstub=trace,nrk::arch::gdb=trace");
    }

    #[test]
    fn parse_test() {
        let args = "./kernel test=userspace";
        let ba = CommandLineArguments::from_str(args);
        assert_eq!(ba.test, Some("userspace"));
    }
}
