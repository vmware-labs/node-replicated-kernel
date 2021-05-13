#! /bin/bash

#
# runs or builds the docker container
#
# to force building, execute with 'force-build'
#
# Note: add yourself to the docker group (see website) to run this without root

# the root directory (corresponds to the git)
ROOT=$(git rev-parse --show-toplevel)

# the user ID and name of the current user
USER_ID=$(id -u)
USER_NAME=$(whoami)

# the image name to be built
IMAGE=nrkbuild

if [[ "$1" = "force-build" ]]; then
    echo "trigger force build (removing any existing image)"
    # remove the container
    docker container rm ${IMAGE}

    # remove the image
    docker image rm -f ${IMAGE}
fi

# check if there is such an image or
if ! docker image ls | grep ${IMAGE} > /dev/null; then
    echo "docker image ${IMAGE} does not exist. building it."
    docker build --build-arg arg_uid="${USER_ID}" --build-arg arg_user="${USER_NAME}" \
                 -t ${IMAGE} "${ROOT}/scripts"
fi

# run the image interactively. we automatically mount the source directory in /source
docker run -i -t --rm --name ${IMAGE} --mount type=bind,source="${ROOT}",target=/source ${IMAGE}
