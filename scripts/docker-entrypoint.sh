#! /bin/bash

#
# the docker entry point -- setup environment and execute command / drop into shell
#

echo "================================================"
echo "Build docker container"
echo "================================================"

# source the cargo environment
source $HOME/.cargo/env

# this is the docker entrypoint
cd /source


echo "setting nightly build chain performing rustup update "
cd kernel
rustup default nightly
cd ..
rustup default nightly

# ensure rustup is up to date
rustup update

echo "starting shell"
if [ "$1" == "" ]; then
    exec "/bin/bash"
else
    exec "$@"
fi