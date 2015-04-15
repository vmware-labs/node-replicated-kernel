# Bespin

Bespin is an (experimental) OS kernel for x86-64 machines written in rust. It
currently does not do much except for serial output, interrupt handling and
running a rust hello world program in user-space.

## Setting up
Currently this is known to work on latest Ubuntu 14.04 using rust-nightly (rust
beta will not work due to use of unstable features).

### Pre-requisites
* We build bespin using the tup build system. You can find information on
  how to obtain tup for your platform here: http://gittup.org/tup/
  On Ubuntu Linux, just do:
```
$ sudo apt-add-repository 'deb http://ppa.launchpad.net/anatol/tup/ubuntu precise main'
$ sudo apt-get update
$ sudo apt-get install tup
```

* Use the latest rust-nightly compiler to build the code:
```
$ curl -s https://static.rust-lang.org/rustup.sh | sudo sh -s -- --channel=nightly
```
Bespin uses rust libcore, so you will also need the libcore sources
to build and link with Bespin.
```
$ wget https://static.rust-lang.org/dist/rustc-nightly-src.tar.gz
$ tar zxvf rustc-nightly-src.tar.gz
```

* Install the qemu emulator for testing:
```
$ sudo apt-get install qemu qemu-kvm
```

### Check-out the sources
1. git clone git@github.com:gz/bespin.git
1. cd bespin
1. git submodule init
1. git submodule update
1. cp -rf ../rustc-nightly/src/libcore lib/core

### Set-up build
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