#!/usr/bin/env bash
set -exu

# Install QEMU
if [ ! -x "$(command -v qemu-system-x86_64)" ]; then
    if [ "$(uname)" == "Darwin" ]; then
        brew install qemu
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        sudo apt-get update
        sudo apt-get install -y qemu qemu-kvm
    fi
fi


# Make sure rust is up-to-date
if [ ! -x "$(command -v rustup)" ] ; then
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
fi
source $HOME/.cargo/env
rustup default nightly
rustup component add rust-src
rustup update

# Install xargo
if [ ! -x "$(command -v xargo)" ]; then 
    cargo install xargo
fi
