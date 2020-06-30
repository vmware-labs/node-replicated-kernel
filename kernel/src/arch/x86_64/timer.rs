//! Timer API

use super::kcb::get_kcb;
use apic::ApicDriver;

/// Default when to raise the next timer irq (in rdtsc ticks)
pub const DEFAULT_TIMER_DEADLINE: u64 = 2_000_000_000;

/// Register a periodic timer to advance replica
///
/// TODO(api): Ideally this should come from Instant::now() +
/// Duration::from_millis(10) and for that we need a way to reliably
/// convert between TSC and Instant
pub fn set(deadline: u64) {
    let kcb = get_kcb();
    let mut apic = kcb.arch.apic();
    apic.tsc_enable();
    unsafe { apic.tsc_set(x86::time::rdtsc() + deadline) };
}
