// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Timer API

/// Default when to raise the next timer irq (in rdtsc ticks)
pub(crate) const DEFAULT_TIMER_DEADLINE: u64 = 2_000_000_000;

/// Register a periodic timer to advance replica.
pub(crate) fn set(_deadline: u64) {}
