#![allow(warnings)]

use alloc::boxed::Box;
use crossbeam_queue;
use topology::MACHINE_TOPOLOGY;

pub mod process;

/*
use crate::arch::process::Ring3Process;
use crate::kcb;

pub fn schedule_process(process: Box<Ring3Process>) {
    let no = kcb::get_kcb().arch.swap_current_process(process);
    assert!(no.is_none());

    unsafe {
        let rh = kcb::get_kcb()
            .arch
            .current_process()
            .as_mut()
            .map(|p| p.start());
        rh.unwrap().resume()
    }
}

/// Determines which process to run next and executes it on the current CPU.
pub fn schedule() -> ! {
    unimplemented!()
}
*/

/// Errors that the scheduler/process logic can return.
#[derive(Debug)]
enum SchedulerError<P> {
    NothingToRun,
    OutOfCapacity(P),
}

/// A MPMC queue that contains processes.
struct FifoScheduler<P: process::Process> {
    queue: crossbeam_queue::ArrayQueue<P>,
}

impl<P: process::Process> FifoScheduler<P> {
    pub fn new() -> Self {
        let capacity = (MACHINE_TOPOLOGY.num_threads() / MACHINE_TOPOLOGY.num_packages()) * 5;
        FifoScheduler::with_capacity(capacity)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let queue = crossbeam_queue::ArrayQueue::<P>::new(capacity);
        FifoScheduler::<P> { queue }
    }

    pub fn insert(&self, process: P) -> Result<(), SchedulerError<P>> {
        self.queue
            .push(process)
            .map_err(|e| SchedulerError::OutOfCapacity(e.0))
    }

    fn next(&self) -> Result<P, SchedulerError<P>> {
        self.queue.pop().map_err(|_e| SchedulerError::NothingToRun)
    }

    pub fn schedule(&self, old: P) -> Result<P, SchedulerError<P>> {
        self.insert(old)?;
        self.next()
    }
}

#[cfg(test)]
mod test {
    use super::process::Process;
    use super::process::ResumeHandle;
    use super::*;

    #[derive(Debug, PartialEq)]
    struct ModelProcess {
        ident: &'static str,
    }

    impl ModelProcess {
        fn new(ident: &'static str) -> ModelProcess {
            ModelProcess { ident }
        }
    }

    impl Process for ModelProcess {
        fn start(&mut self) -> ResumeHandle {
            ResumeHandle {}
        }

        fn resume(&self) -> ResumeHandle {
            ResumeHandle {}
        }

        fn upcall(&mut self, vector: u64, exception: u64) -> ResumeHandle {
            ResumeHandle {}
        }

        fn maybe_switch_vspace(&self) {}
    }

    #[test]
    fn round_robin() {
        let rrs = FifoScheduler::with_capacity(2);
        let p1 = ModelProcess::new("test1");
        let p2 = ModelProcess::new("test2");
        rrs.insert(p2);

        let mut current = p1;
        for i in 0..10 {
            let ident_before_schedule = current.ident;
            current = rrs.schedule(current).expect("No thread to schedule?");
            assert_ne!(current.ident, ident_before_schedule);
        }
    }

    #[test]
    fn insert_next() {
        let rrs = FifoScheduler::with_capacity(2);
        let p1 = ModelProcess::new("test1");
        let p2 = ModelProcess::new("test2");

        rrs.insert(p1).expect("Can't push");
        rrs.insert(p2).expect("Can't push");

        let rp1 = rrs.next().expect("Can't push");
        assert_eq!(rp1.ident, "test1");
        let rp2 = rrs.next().expect("Can't push");
        assert_eq!(rp2.ident, "test2");

        rrs.insert(rp1).expect("Can't push");
        rrs.insert(rp2).expect("Can't push");

        let p3 = ModelProcess::new("test3");
        if let Err(SchedulerError::OutOfCapacity(rp3)) = rrs.insert(p3) {
            assert_eq!(rp3.ident, "test3");
        } else {
            panic!("Not out of capacity?");
        }

        let rp = rrs.queue.pop().expect("Can't pop");
        assert_eq!(rp.ident, "test1");
    }

    #[test]
    fn scheduler_queue_push_pop() {
        let rrs = FifoScheduler::with_capacity(10);
        let p = ModelProcess::new("test1");
        rrs.queue.push(p).expect("Can't push");

        let rp = rrs.queue.pop().expect("Can't pop");
        assert_eq!(rp.ident, "test1");
    }

    #[test]
    fn scheduler_queue_capacity() {
        let rrs = FifoScheduler::with_capacity(3);

        for ident in &["test1", "test2", "test3"] {
            let p = ModelProcess::new(ident);
            rrs.queue.push(p).expect("Can't push");
        }
        let p = ModelProcess::new("overflow");
        rrs.queue.push(p).expect_err("Can push?");

        let rp = rrs.queue.pop().expect("Can't pop");
        assert_eq!(rp.ident, "test1");

        let rp = rrs.queue.pop().expect("Can't pop");
        assert_eq!(rp.ident, "test2");

        let rp = rrs.queue.pop().expect("Can't pop");
        assert_eq!(rp.ident, "test3");

        let _rp = rrs.queue.pop().expect_err("Can pop?");
    }
}
