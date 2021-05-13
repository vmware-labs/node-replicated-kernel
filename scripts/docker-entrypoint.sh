#! /bin/bash

#
# the docker entry point -- setup environment and execute command / drop into shell
#

echo "================================================"
echo "Build docker container"
echo "================================================"

source /rustversion.sh

# source the cargo environment
source "$HOME/.cargo/env"

# this is the docker entrypoint
cd /source || exit


echo "setting rust versions to ${RUST_VERSION}"
cd kernel || exit
rustup default "${RUST_VERSION}"
cd ..
rustup default "${RUST_VERSION}"

# ensure rustup is up to date and we got the sources
rustup component add rust-src
rustup update

if [ "$1" == "" ]; then
    echo "starting shell..."
    exec "/bin/bash"
    exit 0
else
    echo "executing '$*'"
    exec "$*"
fi