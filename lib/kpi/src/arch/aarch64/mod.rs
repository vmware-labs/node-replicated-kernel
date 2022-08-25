// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Defines the public kernel interface that is specific to x86-64.

#![allow(unaligned_references)]

use core::fmt;
use core::ops::Range;

use armv8::aarch64::vm::granule4k::*;

pub const ROOT_TABLE_SLOT_SIZE: usize = L1_TABLE_ENTRIES * HUGE_PAGE_SIZE;
