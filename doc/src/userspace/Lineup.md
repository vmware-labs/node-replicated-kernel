# Lineup

Lineup is a user-space, cooperative thread scheduler that runs green-threads
(user-level threads). It supports many synchronization primitives (mutex,
rwlock, conditional variables, barriers etc.), thread-local storage, and has
some basic support for multi-threading. It uses
[fringe](https://crates.io/crates/fringe) for compiler-assisted
context-switching. The scheduler code is found in `lib/lineup`.

## Upcalls

The kernel can notify the scheduler about events through an up-call mechanism,
for example to notify about more available cores (or removal of cores), to
forward device interrupts, or page-faults from kernel to user-space.

The mechanism for this is inspired by scheduler activations: The kernel and
user-space program agree on a common save area to store a CPU context (on a
per-core basis). If an event arrives at the kernel, it will save the current CPU
context (registers etc.) in the agreed upon save-area and resume the process
with a new (mostly empty) context that invokes the pre-registered upcall handler
instead. The upcall handler gets all information about the event that triggered
the interruption through function arguments so it can then take appropriate
measures to react. After the event is handled, the upcall handler can read the
previous context (from before the interruption) from the common save area and
decide to resume where computation left off before the upcall (or decide not to
continue with this context).
