# lineup

A light-weight threading library with a cooperative scheduler.
Can be used in `no_std` environments and supports the following features:

* Mutexes
* Conditional variables
* Reader/Writer locks
* Semaphores
* Thread local storage
* Multicore support (per-core scheduler lists)

## Testing

Run as: `cargo test --release`
