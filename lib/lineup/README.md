# lineup

A light-weight threading library that includes with a cooperative 
scheduler. This can be used in no_std environments
and supports the following features:

  * Mutexes
  * Conditional variables
  * Reader/Writer Locks
  * Semaphores
  * Thread local storage

## Testing
Run as: RUST_TEST_THREADS=1 cargo test --release