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

Run as: `RUST_TEST_THREADS=1 cargo test --release`

`RUST_TEST_THREADS=1` is technically not necessary but tests are less flaky if
the system has not enough cores. e.g., this can sometimes happen if a test
duration doesn't execute long enough:

```log
---- rwlock::test_rwlock_smp stdout ----
thread 'main' panicked at 'dropped unfinished Generator', /rustc/2113659479a82ea69633b23ef710b58ab127755e/src/libcore/macros/mod.rs:34:9
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

The `scheduler_is_parallel` test also checks timing and can be flaky.
