// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::{self, Display, Formatter};

extern crate csv;
extern crate hwloc2;
extern crate rexpect;
extern crate serde;

pub mod builder;
pub mod helpers;
pub mod rackscale_runner;
pub mod redis;
pub mod runner_args;

/// Different ExitStatus codes as returned by NRK.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum ExitStatus {
    /// Successful exit.
    Success,
    /// ReturnFromMain: main() function returned to arch_indepdendent part.
    ReturnFromMain,
    /// Encountered kernel panic.
    KernelPanic,
    /// Encountered OOM.
    OutOfMemory,
    /// Encountered an interrupt that led to an exit.
    UnexpectedInterrupt,
    /// General Protection Fault.
    GeneralProtectionFault,
    /// Unexpected Page Fault.
    PageFault,
    /// Unexpected process exit code when running a user-space test.
    UnexpectedUserSpaceExit,
    /// Exception happened during kernel initialization.
    ExceptionDuringInitialization,
    /// An unrecoverable error happened (double-fault etc).
    UnrecoverableError,
    /// Kernel exited with unknown error status... Update the script.
    Unknown(i32),
}

impl From<i32> for ExitStatus {
    fn from(exit_code: i32) -> Self {
        match exit_code {
            0 => ExitStatus::Success,
            1 => ExitStatus::ReturnFromMain,
            2 => ExitStatus::KernelPanic,
            3 => ExitStatus::OutOfMemory,
            4 => ExitStatus::UnexpectedInterrupt,
            5 => ExitStatus::GeneralProtectionFault,
            6 => ExitStatus::PageFault,
            7 => ExitStatus::UnexpectedUserSpaceExit,
            8 => ExitStatus::ExceptionDuringInitialization,
            9 => ExitStatus::UnrecoverableError,
            _ => ExitStatus::Unknown(exit_code),
        }
    }
}

impl Display for ExitStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let desc = match self {
            ExitStatus::Success => "Success!",
            ExitStatus::ReturnFromMain => {
                "ReturnFromMain: main() function returned to arch_indepdendent part"
            }
            ExitStatus::KernelPanic => "KernelPanic: Encountered kernel panic",
            ExitStatus::OutOfMemory => "OutOfMemory: Encountered OOM",
            ExitStatus::UnexpectedInterrupt => "Encountered unexpected Interrupt",
            ExitStatus::GeneralProtectionFault => {
                "Encountered unexpected General Protection Fault: "
            }
            ExitStatus::PageFault => "Encountered unexpected Page Fault",
            ExitStatus::UnexpectedUserSpaceExit => {
                "Unexpected process exit code when running a user-space test"
            }
            ExitStatus::ExceptionDuringInitialization => {
                "Got an interrupt/exception during kernel initialization"
            }
            ExitStatus::UnrecoverableError => "An unrecoverable error happened (double-fault etc).",
            ExitStatus::Unknown(_) => {
                "Unknown: Kernel exited with unknown error status... Update the code!"
            }
        };

        write!(f, "{}", desc)
    }
}
