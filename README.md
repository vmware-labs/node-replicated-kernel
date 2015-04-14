# Bespin

Bespin is an (experimental) OS kernel for x86-64 machines written in rust. It
currently does not do much except for serial output, interrupt handling and
running a rust hello world program in user-space.

## Setting up
Currently this is known to work on latest Ubuntu 14.04 using rust-nightly (rust
beta will not work due to use of unstable features).

1. Install tup
1. Install rust-nightly
1. Copy libcore
1. Install qemu
1. git clone 
1. cd bespin
1. git submodule init
1. tup init
1. tup variant tup/x86_64.config

## Running Bespin
Build Bespin using tup:
1. `tup`
Next, run Bespin on Qemu:
1. `./run.sh`

## Future Work
M1: Running libcore user-space program
M2: ACPI Integration
M3: Multiprocessor support
M4: PCI support
M5: Rust standard library port