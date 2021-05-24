# Kernel Architecture

The NRK kernel is a small, light-weight (multi-)kernel that provides a
[process abstraction with virtual memory](Process.md), a [coarse-grained
scheduler](Scheduler.md), as well as an [in-memory file-system](Filesystem.md).

One key feature of the kernel is how it scales to many cores (and NUMA
nodes) by relying on data-structure replication with operation logging. We
explain the two main techniques we use for this in the [Node
Replication](NodeReplication.md) and [Concurrent Node
Replication](ConcurrentNodeReplication.md) sections of this chapter.
