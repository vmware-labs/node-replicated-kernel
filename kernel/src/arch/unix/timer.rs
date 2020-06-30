//! Timer API

/// Default when to raise the next timer irq (in rdtsc ticks)
pub const DEFAULT_TIMER_DEADLINE: u64 = 2_000_000_000;

/// Register a periodic timer to advance replica.
pub fn set(deadline: u64) {}
