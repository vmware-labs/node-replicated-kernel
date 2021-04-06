#
# Dockerfile for the build container
#
FROM ubuntu:20.04
LABEL maintainer="Reto Achermann <achreto@gmail.com>"

# arguments for this docker container
# the user name and id of the container
ARG arg_uid=1000
ARG arg_user=user

# set the environment arguments (will be used in the script)
ENV ENV_USER=$arg_user
ENV ENV_UID=$arg_uid

# copy the enntrypoint and setup files into the image
COPY docker-setup.sh /docker-setup.sh
COPY generic-setup.sh /generic-setup.sh
COPY docker-entrypoint.sh /entrypoint.sh

# run the setup scripts
RUN  /bin/bash docker-setup.sh

# set the user for this docker
USER $arg_user

# entrypoint for the docker image
ENTRYPOINT ["/entrypoint.sh"]