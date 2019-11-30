pub struct ResumeHandle;

/// Abstract definition of a process.
pub trait Process {
    fn start(&mut self) -> ResumeHandle;
    fn resume(&self) -> ResumeHandle;
    fn upcall(&mut self, vector: u64, exception: u64) -> ResumeHandle;
    fn maybe_switch_vspace(&self);
}
