# Bespin

Bespin is an (experimental) OS kernel for x86-64 (amd64) machines written in
rust. It currently does not do much except for serial output, interrupt handling and loading ELF binaries.

### Check-out the sources
1. `git clone git@github.com:gz/bespin.git`
1. `cd bespin`
1. `git submodule init`
1. `git submodule update`

### Install dependencies
1. `sudo apt-get install qemu qemu-kvm`
1. `curl https://sh.rustup.rs -sSf | sh`
1. `rustup default nightly`
1. `rustup component add rust-src`
1. `rustup update`
1. `cargo install xargo`

### Build and run
1. `RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build --target=bespin`
1. `bash -x ./run.sh`

## Future Work
 * [x] Milestone 1: Running libcore user-space program
 * [ ] Milestone 2: ACPI Integration
 * [ ] Milestone 3: Multiprocessor support
 * [ ] Milestone 4: PCI support
 * [ ] Milestone 5: Rust standard library port
