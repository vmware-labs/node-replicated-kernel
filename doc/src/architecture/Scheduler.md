# Scheduler

In NRK, the kernel-level scheduler is a coarse-grained scheduler that allocates
CPUs to processes. Processes make system calls to request for more cores and to
give them up. The kernel notifies processes core allocations and deallocations
via upcalls. To run on a core, a process allocates executor objects (*i.e.,* the
equivalent of a "kernel" thread) that are used to dispatch a given process on
a CPU. An executor mainly consists of two userspace stacks (one for the upcall
handler and one for the initial stack) and a region to save CPU registers and
other metadata. Executors are allocated lazily but a process keeps a per-NUMA
node cache to reuse them over time.

In the process, a userspace scheduler reacts to upcalls indicating the addition
or removal of a core, and it makes fine-grained scheduling decisions by
dispatching threads accordingly. This design means that the kernel is only
responsible for coarse-grained scheduling decisions, and it implements a global
policy of core allocation to processes.

The scheduler uses a sequential hash table wrapped with NR to map each process
id to a process structure and to map process executors to cores. It has
operations to create or destroy a process; to allocate and deallocate executors
for a process; and to obtain an executor for a given core.
