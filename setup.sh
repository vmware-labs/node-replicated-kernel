#!/usr/bin/env bash
set -ex

source scripts/generic-setup.sh

# system wide dependencies (packages)
install_build_dependencies
install_run_dependencies

# installing rust
bootstrap_rust
install_rust_build_dependencies
install_rust_run_dependencies

# set permissions for tcpdump for vmxnet3 tests
sudo setcap cap_net_raw,cap_net_admin=eip `which tcpdump`
