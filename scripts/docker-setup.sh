#! /bin/bash

#
# script used to configure the docker container
# this runs inside docker to install required packages and create the user
#

set -exu

source /generic-setup.sh

export RUST_VERSION=nightly-2021-03-16
echo "export RUST_VERSION=${RUST_VERSION}" > /rustversion.sh

echo "installing dependencies..."
install_build_dependencies

# create the user and the directory
groupadd -g "${ENV_UID}"  "${ENV_USER}"
useradd "${ENV_USER}" -u "${ENV_UID}" -g "${ENV_UID}" -m -s /bin/bash


echo "switching to user ${ENV_USER}"
export HOME=/home/${ENV_USER}

su - "${ENV_USER}"
cd "$HOME"

# bootstrap rust
bootstrap_rust
install_rust_build_dependencies

# now make sure everything is owned by the user
chown -R "${ENV_USER}":"${ENV_USER}" "/home/${ENV_USER}"

# make the entrypoint executable
chmod 755 /entrypoint.sh
