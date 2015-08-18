#!/usr/bin/env bash

# Install required packages
sudo apt-add-repository 'deb http://ppa.launchpad.net/anatol/tup/ubuntu precise main'
sudo apt-get update
sudo apt-get install qemu qemu-kvm tar wget curl tup

# Install nightly rust
curl -s https://static.rust-lang.org/rustup.sh | sudo sh -s -- --channel=nightly

# Remove old rust sources
rm -rf lib/core
rm -rf lib/collections
rm -rf lib/alloc
rm -rf lib/rustc_unicode

# Get new rust sources
rm rustc-nightly-src.tar.gz
rm -rf rustc-nightly/
wget https://static.rust-lang.org/dist/rustc-nightly-src.tar.gz
tar zxvf rustc-nightly-src.tar.gz

# Patching libcore because of LLVM bug.
# see also https://llvm.org/bugs/show_bug.cgi?id=23203
# and https://github.com/rust-lang/rust/issues/26449
cd rustc-nightly
patch -p1 < ../libcore_patch.diff
cd ..

cp -rf rustc-nightly/src/libcore lib/core
cp -rf rustc-nightly/src/liballoc lib/alloc
cp -rf rustc-nightly/src/libcollections lib/collections
cp -rf rustc-nightly/src/librustc_unicode lib/rustc_unicode

# Clean-up unneeded files
rm rustc-nightly-src.tar.gz
rm -rf rustc-nightly/