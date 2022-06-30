#!/bin/bash
set -ex

#
# Makes sure that tests in CI will pass (hopefully).
#

# check formatting
cd ..
cargo fmt -- --check
cd kernel

# build kernel
RUST_TARGET_PATH=`pwd`/src/arch/x86_64 cargo build -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem -v --target=x86_64-nrk

# Try to compile with all/most of the code enabled
python3 run.py --kfeatures ethernet shmem rackscale integration-test gdb --kgdb --norun
# run kernel
python3 run.py

# run unix architecture
cargo run

# compile init binary
cd ../usr/init
RUST_TARGET_PATH=`pwd`/../ cargo build -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nrk-none --color always --release --all-features
cd ../../kernel

# run integration tests
RUST_TEST_THREADS=1 cargo test  --features smoke -- --nocapture

# Testing stuff under lib/
cd ../lib/apic && cargo test --all-features
cd ../bootloader_shared && cargo test --all-features
cd ../kpi && cargo test --all-features
cd ../vibrio && cargo test --all-features
cd  ../vmxnet3 && cargo test --all-features
cd ../rpc && cargo test --all-features

# Documentation
cd ../../doc && mdbook build