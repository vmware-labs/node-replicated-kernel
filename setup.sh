#!/usr/bin/env bash

# Install required packages
sudo apt-get update
sudo apt-get install qemu qemu-kvm

rustup default nightly
rustup component add rust-src
rustup update
cargo install xargo
