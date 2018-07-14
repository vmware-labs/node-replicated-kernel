# Bespin

Bespin is an (experimental) OS kernel for x86-64 (amd64) machines written in
rust. It currently does not do much except for serial output, interrupt handling and loading ELF binaries.

### Check-out the source tree
1. `git clone git@github.com:gz/bespin.git`
1. `cd bespin`
1. `git submodule init`
1. `git submodule update`

### Install dependencies
Run `bash setup.sh`

### Build and run
1. `cd kernel`
1. ```RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build --target=bespin```
1. `bash ./run.sh`

## Future Work
 * [x] Milestone 1: Running libcore user-space program
 * [ ] Milestone 2: ACPI Integration
 * [ ] Milestone 3: Multiprocessor support
 * [ ] Milestone 4: PCI support
 * [ ] Milestone 5: Rust standard library port
