# Testing

If you've found and fixed a bug, we better write a test for it. nrk uses
several test-frameworks and methodologies to ensure everything works as
expected:

- Regular unit tests: Those can be executed running `cargo test` in the project
  folder. Sometimes adding `RUST_TEST_THREADS=1` is necessary due to the
  structure of the runner/frameworks used. This should be indicated in the
  individual READMEs.
- A slightly more exhaustive variant of unit tests is property based testing. We
  use [proptest](https://github.com/altsysrq/proptest) to make sure that the
  implementation of kernel sub-systems corresponds to a reference model
  implementation.
- Integration tests are found in the kernel, they typically launch a qemu
  instance and use [rexpect](https://github.com/philippkeller/rexpect) to
  interact with the guest.
- Fuzz testing: TBD.

## Running tests

To run the unit tests of the kernel:

1. `cd kernel`
1. `RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --bin nrk`

To run the integration tests of the kernel:

1. `cd kernel`
1. `RUST_TEST_THREADS=1 cargo test --test integration-test`

If you would like to run a specific integration test you can pass it with `--`:

1. `RUST_TEST_THREADS=1 cargo test --test integration-test -- userspace_smoke`

In case an integration test fails, adding `--nocapture` at the end (needs to
come after the `--`) will make sure that the underlying `run.py` invocations are
printed to the stdout.

Note: Parallel testing for he kernel is not possible at the moment due to
reliance on build flags for testing.

## Writing a unit-test for the kernel

Typically these can just be declared in the code using `#[test]`. Note that
tests by default will run under the `unix` platform. A small hack is necessary
to allow tests in the `x86_64` to compile and run under unix too: When run on a
x86-64 unix platform, the platform specific code of the kernel in `arch/x86_64/`
will be included as a module named `x86_64_arch` whereas normally it would be
`arch`. This is a double-edged sword: we can now write tests that test the
actual bare-metal code (great), but we can also easily crash the test process by
calling an API that writes an MSR for example (e.g, things that would require
ring 0 priviledge level).

## Writing an integration test for the kernel

Integration tests typically spawns a QEMU instance and beforehand compiles the
kernel/user-space with a custom set of Cargo feature flags. Then it parses the
qemu output to see if it gave the expected output. Part of those custom compile
flags will also choose a different main() function than the one you're seeing
(which will go off to load and schedule user-space programs for example).

There is two parts to the integration test.

- The host side (that will go off and spawn a qemu instance) for running the
  integration tests. It is found in `kernel/tests/integration-test.rs`.
- The corresponding main functions in the kernel that gets executed for a
  particular example are located at `kernel/src/integration_main.rs`

To add a new integration test the following tests may be necessary:

1. Modify `kernel/Cargo.toml` to add a feature (under `[features]`) for the test
   name.
1. Optional: Add a new `xmain` function and test implementation in it to
   `kernel/src/integration_main.rs` with the used feature name as an annotation.
   It may also be possible to re-use an existing xmain function, in that case
   make not of the feature name used to include it.
1. Add a runner function to `kernel/tests/integration-test.rs` that builds the
   kernel with the cargo feature runs it and checks the output.
