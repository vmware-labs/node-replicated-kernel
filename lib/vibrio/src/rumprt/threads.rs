// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! rumpkernel "kernel" threads implementation.

use core::ops::Add;
use core::sync::atomic::Ordering;

use cstr_core::CStr;
use lineup::tls2::Environment;
use log::{info, trace};
use rawtime::{Duration, Instant};

use super::{c_int, errno};

#[allow(non_camel_case_types)]
pub type rumplwpop = u32;

pub const RUMPLWPOP_RUMPUSER_LWP_CREATE: rumplwpop = 0;
pub const RUMPLWPOP_RUMPUSER_LWP_DESTROY: rumplwpop = 1;
pub const RUMPLWPOP_RUMPUSER_LWP_SET: rumplwpop = 2;
pub const RUMPLWPOP_RUMPUSER_LWP_CLEAR: rumplwpop = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lwp {
    _unused: [u8; 0],
}

/// Create a schedulable host thread context. The rump kernel will call
/// this interface when it creates a kernel thread.
/// The scheduling policy for the new thread is defined by the hypervisor.
/// In case the hypervisor wants to optimize the scheduling of the threads,
/// it can perform heuristics on the thrname, priority and cpuidx parameters.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_create(
    fun: Option<unsafe extern "C" fn(arg1: *mut u8) -> *mut u8>,
    arg: *mut u8,
    name: *const u8,
    mustjoin: i64,
    priority: i64,
    cpuidx: i32,
    cookie: *mut *mut u8,
) -> i64 {
    let tname = CStr::from_ptr(name as *const i8)
        .to_str()
        .unwrap_or("[unknown]");

    let core_id = if cpuidx == -1 { 0 } else { cpuidx };
    let gtid = crate::rumprt::CPUIDX_TO_GTID.lock()[core_id as usize];

    let s = lineup::tls2::Environment::thread();
    let tid = s.spawn_on_core(fun, arg, gtid);
    trace!(
        "rumpuser_thread_create {} {:?} {:p} join={} prio={} cpu={} gtid={:?} cookie={:p} tid={:?}",
        tname,
        fun,
        arg,
        mustjoin,
        priority,
        cpuidx,
        gtid,
        cookie,
        tid
    );

    0
}

/// Called when a thread created with rumpuser_thread_create() exits.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_exit() {
    let t = lineup::tls2::Environment::thread();
    loop {
        info!(
            "rumpuser_thread_exit {:?}",
            lineup::tls2::Environment::tid()
        );
        t.block();
        unreachable!("rumpuser_thread_exit");
    }
}

/// Wait for a joinable thread to exit. The cookie matches the value from rumpuser_thread_create().
#[no_mangle]
pub unsafe extern "C" fn rumpuser_thread_join(_cookie: *mut u8) -> i64 {
    unreachable!("rumpuser_thread_join");
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwpop(op: rumplwpop, lwp: *const lwp) -> i64 {
    trace!(
        "{:?} rumpuser_curlwpop op={} lwp={:p}",
        lineup::tls2::Environment::tid(),
        op,
        lwp
    );
    let t = lineup::tls2::Environment::thread();

    if op == RUMPLWPOP_RUMPUSER_LWP_SET {
        t.set_lwp(lwp as *mut u64);
    }
    if op == RUMPLWPOP_RUMPUSER_LWP_CLEAR {
        assert!(t.rump_lwp.load(Ordering::SeqCst) == lwp as *mut u64);
        t.set_lwp(core::ptr::null_mut());
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rumpuser_curlwp() -> *mut lwp {
    let t = lineup::tls2::Environment::thread();
    t.rump_lwp.load(Ordering::SeqCst) as *mut lwp
}

/// int rumpuser_clock_sleep(int enum_rumpclock, int64_t sec, long nsec)
///
/// enum_rumpclock   In case of RUMPUSER_CLOCK_RELWALL, the sleep should last
/// at least as long as specified.  In case of
/// RUMPUSER_CLOCK_ABSMONO, the sleep should last until the
/// hypervisor monotonic clock hits the specified absolute
/// time.
#[no_mangle]
pub unsafe extern "C" fn rumpuser_clock_sleep(enum_rumpclock: u32, sec: i64, nanos: u64) -> c_int {
    trace!(
        "{:?} rumpuser_clock_sleep({}, {}, {})",
        Environment::tid(),
        enum_rumpclock,
        sec,
        nanos
    );

    let mut nlocks = 0;
    super::rumpkern_unsched(&mut nlocks, None);

    let (until, retval) = match enum_rumpclock as u64 {
        super::RUMPUSER_CLOCK_ABSMONO => {
            let now = Instant::now();
            (
                // TODO: this may negative overflow panic on bad timed irq
                Instant::from_nanos((sec as u128) * 1_000_000_000 + nanos as u128) - now,
                0,
            )
        }
        super::RUMPUSER_CLOCK_RELWALL => (
            Duration::from_secs(sec as u64).add(Duration::from_nanos(nanos)),
            0,
        ),
        _ => (Duration::from_secs(0), errno::EINVAL),
    };

    let t = Environment::thread();
    t.sleep(until);

    super::rumpkern_sched(&nlocks, None);

    retval
}
