#!/bin/bash
set -ex

# build
RUSTFLAGS="-D warnings -C link-arg=-T./kernel/src/arch/x86_64/link.ld -C link-arg=-n -C target-feature=+sse" RUST_TARGET_PATH=`pwd`/src/arch/x86_64  xargo build -vv --target=x86_64-bespin

# run
python run.py

# unix
cargo run

# test
RUST_TEST_THREADS=1 cargo test
cargo +nightly fmt --package bespin -- --check