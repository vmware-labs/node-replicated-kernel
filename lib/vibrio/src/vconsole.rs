// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A simple virtual console for user-space programs (getchar et. al.).
//!
//! Needs to be a proper serial driver.

static COM1_IRQ: u64 = 4 + 32;

pub fn init() {
    crate::syscalls::Irq::irqalloc(COM1_IRQ, 0).ok();
}

fn _getchar() -> Option<char> {
    None
}
