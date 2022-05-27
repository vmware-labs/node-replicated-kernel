// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Timer API

use apic::ApicDriver;

/// Default when to raise the next timer irq (in rdtsc ticks)
pub(crate) const DEFAULT_TIMER_DEADLINE: u64 = 2_000_000_000;

/// Register a periodic timer to advance replica
///
/// TODO(api): Ideally this should come from Instant::now() +
/// Duration::from_millis(10) and for that we need a way to reliably
/// convert between TSC and Instant
pub(crate) fn set(deadline: u64) {
    let mut apic = super::irq::LOCAL_APIC.borrow_mut();
    apic.tsc_enable();
    unsafe { apic.tsc_set(x86::time::rdtsc() + deadline) };
}
