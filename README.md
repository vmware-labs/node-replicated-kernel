# Node Replicated Kernel

The Node Replicated Kernel is an (experimental) research OS kernel for x86-64
(amd64) machines written in rust. You can read more about it
[here](https://nrkernel.systems/book/).

## Installation

### Check-out the source tree

1. `git clone <repo-url> nrk`
1. `cd nrk`
1. Note: In case you don't have the SSH key of your machine registered with a github account,
you need to convert the submodule URLs to the https protocol, to do so run:
`sed -i'' -e 's/git@github.com:/https:\/\/github.com\//' .gitmodules`
1. `git submodule update --init`

### Install dependencies

Run `bash setup.sh`, this will install required dependencies on Linux to build and run nrk.

### Build and run

1. `cd kernel`
1. `python3 ./run.py`

If you just want to compile the code you can also execute `run.py` with the
`--norun` flag.

## Development

### Testing

To run the unit tests of the kernel:

1. `cd kernel`
1. `RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --bin nrk`

To run the integration tests of the kernel:

1. `cd kernel`
1. `RUST_TEST_THREADS=1 cargo test --features smoke --test integration-test`

If you would like to run a specific integration test you can pass it with `--`:

1. `RUST_TEST_THREADS=1 cargo test --test integration-test -- --nocapture userspace_smoke`

> Note: Parallel testing is not possible at the moment due to reliance on build flags for testing.

### Submitting a change

Update latest master:

1. `git checkout master`
1. `git pull`
1. `git submodule update --init`

Create a new feature branch:

1. `git checkout -b <BRANCH-NAME>`
1. Make changes in code.

Make sure that the code compiles without warnings, is properly formatted and passes tests:

1. `cd kernel`
1. `bash commitable.sh`

Commit changes and push

1. `git add <CHANGED-FILES>`
1. `git commit`
1. `git push -u origin <BRANCH-NAME>`
1. Create a Pull Request on GitHub.
