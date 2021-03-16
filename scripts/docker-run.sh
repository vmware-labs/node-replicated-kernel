#! /bin/bash

#
# runs or builds the docker container
#
# to force building, execute with 'force-build'

# the root directory (corresponds to the git)
ROOT=$(git rev-parse --show-toplevel)

# the user ID and name of the current user
USER_ID=$(id -u)
USER_NAME=$(whoami)

# the image name to be built
IMAGE=bespinbuild

# check if there is such an image or
if [[ "$1"="force-build" || `docker image ls | grep ${IMAGE}` ]]; then
    echo "docker image ${IMAGE} does not exist. building it."
    docker build --build-arg arg_uid=${USER_ID} --build-arg arg_user=${USER_NAME} \
                      -t ${IMAGE} ${ROOT}/scripts

fi

# run the image interactively. we automatically mount the source directory in /source
docker run -i -t --mount type=bind,source=${ROOT},target=/source ${IMAGE}
