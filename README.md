# Bespin

[![Build Status](https://travis-ci.org/gz/bespin.svg)](https://travis-ci.org/gz/bespin) 

Bespin is an (experimental) OS kernel for x86-64 (amd64) machines written in
rust. It currently does not do much except for serial output, interrupt handling and loading ELF binaries.

### Check-out the source tree
1. `git clone git@github.com:gz/bespin.git`
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

## Testing
1. `cd kernel`
1. `RUST_TEST_THREADS=1 cargo test --test integration-test`

Note: Parallel testing is not possible at the moment due to reliance on build flags for testing.

## Future Work
 * [x] Milestone 1: Running libcore user-space program
 * [ ] Milestone 2: ACPI Integration
 * [ ] Milestone 3: Multiprocessor support
 * [ ] Milestone 4: PCI support
 * [ ] Milestone 5: Rust standard library port
