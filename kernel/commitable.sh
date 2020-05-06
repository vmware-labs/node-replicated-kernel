#!/bin/bash
set -ex

# check formatting
cargo +nightly fmt --package bespin -- --check

# build
RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build -v --target=x86_64-bespin -Zfeatures=all

# run
python3 run.py

# unix
cargo run

# test
RUST_TEST_THREADS=1 cargo test  --features smoke -- --nocapture
