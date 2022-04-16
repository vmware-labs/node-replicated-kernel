// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::arch::global_asm;

#[cfg(target_os = "none")]
global_asm!(include_str!("isr.S"), options(att_syntax));
