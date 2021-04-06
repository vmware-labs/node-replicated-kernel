// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! System call layer used by applications.
//!
//! Code in this module is not linked into the kernel.

mod io;
mod macros;
mod memory;
mod process;
mod system;

pub use io::{Fs, Irq};
pub use memory::{PhysicalMemory, VSpace};
pub use process::Process;
pub use system::System;
