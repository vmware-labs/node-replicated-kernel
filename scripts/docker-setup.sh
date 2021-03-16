#! /bin/bash

#
# script used to configure the docker container
# this runs inside docker to install required packages and create the user
#

set -exu

echo "installing dependencies..."
apt-get update

apt-get install -y make gcc build-essential curl git zlib1g-dev
apt-get install -y python3 python3-plumbum python3-prctl python3-toml python3-pexpect
apt-get install -y uml-utilities mtools

# For building rump packages (rkapps)
apt-get install -y genisoimage

# create the user and the directory
groupadd -g ${ENV_UID}  ${ENV_USER}
useradd ${ENV_USER} -u ${ENV_UID} -g ${ENV_UID} -m -s /bin/bash


echo "switching to user ${ENV_USER}"
export HOME=/home/${ENV_USER}

su - ${ENV_USER}
cd $HOME
whoami

# Make sure rust is up-to-date
curl https://sh.rustup.rs -sSf | sh -s -- -y

# source the home directory
source $HOME/.cargo/env

# set the default toolchain to nightly
rustup default nightly

# adding the rust-src component
rustup component add rust-src

# perform update
rustup update

# Install xargo (used by build)
cargo install xargo

# Install mdbook for documents
cargo install mdbook

# now make sure everything is owned by the user
chown -R ${ENV_USER}:${ENV_USER} /home/${ENV_USER}

# make the entrypoint executable
chmod 755 /entrypoint.sh