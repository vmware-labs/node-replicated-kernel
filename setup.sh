#!/usr/bin/env bash

# Install required packages
sudo apt-get update
sudo apt-get install qemu qemu-kvm

curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
rustup default nightly
rustup component add rust-src
rustup update
cargo install xargo
