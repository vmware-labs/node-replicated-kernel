# Bespin

[![Build Status](https://travis-ci.org/gz/bespin.svg)](https://travis-ci.org/gz/bespin)

Bespin is an (experimental) OS kernel for x86-64 (amd64) machines written in
rust. It currently does not do much except for serial output, interrupt handling and loading ELF binaries.

### Check-out the source tree
1. `git clone <repo-url>`
1. `cd bespin`
1. `git submodule init`
1. `git submodule update`

### Install dependencies
Run `bash setup.sh` this will install rust (nightly), xargo (rust cross compilation tool),
and QEMU on Linux or Mac.

### Install binutils for Mac
If you are testing on Mac OS you have to compile and install your own binutils
to link ELF files. You can execute `bash setup_mac_binutils.sh` to download and compile binutils.

### Build and run
1. `cd kernel`
1. `bash ./run.sh`

If you just want to compile the code you can also execute:
1. ```RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build --target=bespin```
in the kernel directory (run.sh will do that on your behalf).

## Development

### Testing
1. `cd kernel`
1. `RUST_TEST_THREADS=1 cargo test --test integration-test`

Note: Parallel testing is not possible at the moment due to reliance on build flags for testing.

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
1. `cargo +nightly fmt`
1. `RUSTFLAGS='-D warnings' bash ./run.sh`
1. `RUSTFLAGS='-D warnings' RUST_TEST_THREADS=1 cargo test --test integration-test`

Commit changes and push
1. `git add <CHANGED-FILES>`
1. `git commit`
1. `git push -u origin <BRANCH-NAME>`
1. Create a Pull Request on GitHub.

### Adding a new submodule
1. `cd lib`
1. `git submodule add <path-to-repo> <foldername>`

### Removing a submodule
1. Delete the relevant section from the .gitmodules file.
1. Stage the .gitmodules changes: git add .gitmodules.
1. Delete the relevant section from .git/config.
1. Run git rm --cached path_to_submodule (no trailing slash).
1. Run rm -rf .git/modules/path_to_submodule (no trailing slash).

### Future Work
 * [x] Milestone 1: Running libcore user-space program
 * [x] Milestone 2: ACPI Integration
 * [x] Milestone 4: PCI support / Network
 * [ ] Milestone 3: Multiprocessor support
 * [ ] Milestone 5: Rust standard library port
