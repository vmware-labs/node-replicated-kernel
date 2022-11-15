// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Default when to raise the next timer irq (in rdtsc ticks)
pub(crate) const DEFAULT_TIMER_DEADLINE: u64 = 2_000_000_000;

/// Register a periodic timer to advance replica
///
/// TODO(api): Ideally this should come from Instant::now() +
/// Duration::from_millis(10) and for that we need a way to reliably
/// convert between TSC and Instant
pub(crate) fn set(deadline: u64) {
    log::error!("TIMER NOT SET!!! not yet implemented");
}
