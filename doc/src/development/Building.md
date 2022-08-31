# Building

There are two sets of dependencies required for the development process: build
and run dependencies. We typically build, develop and test using the latest
Ubuntu LTS version and run nrk in QEMU. Other Linux systems will probably work
but might require a manual installation of all dependencies. Other operating
systems likely won't work out of the box without some adjustments for code and
the build-process.

## Check-out the source tree

Check out the nrk sources first:

```bash
git clone <repo-url>
cd nrk
```

The repository is structured using [git
submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules). You'll have to
initialize and check-out the submodules separately:

> In case you don't have the SSH key of your machine registered with a github
> account, you need to convert all submodule URLs to use the https protocol
> instead of SSH, to do so run this sed script before proceeding:
>
> `sed -i'' -e 's/git@github.com:/https:\/\/github.com\//' .gitmodules`

```bash
git submodule update --init
```

## Dependencies

If you want to build without [Docker](./Building.html#use-docker), you
can install both build and run dependencies by executing `setup.sh` in the root
of the repository directly on your machine (*this requires the latest Ubuntu
LTS*). The script will install all required OS packages, [install Rust using
`rustup`](https://rustup.rs/) and some additional rust programs and
dependencies. To run rackscale integration tests, you will also have to install
the [DCM-based scheduler dependencies](https://github.com/hunhoffe/nrk-dcm-scheduler).

The build dependencies can be divided into these categories

* Rust (nightly) and the `rust-src` component for compiling the OS
* `python3` (and some python libraries) to execute the build and run script
* Test dependencies (qemu, corealloc, dhcpd, redis-benchmark, socat, graphviz
  etc.)
* Rumpkernel dependencies (gcc, zlib1g etc.)
* Build for documentation ([mdbook](https://github.com/rust-lang/mdBook))

See `scripts/generic-setup.sh` function `install_build_dependencies` for
details.

## Use Docker

We provide scripts to create a docker image which contains all build
dependencies already.

> To use Docker, it needs to be installed in your system. On Ubuntu execute
> the following steps:
>
> ```bash
> sudo apt install docker.io
> sudo service docker restart
> sudo addgroup $USER docker
> newgrp docker
> ```

To create the image execute the following command in the `/scripts` directory.

```bash
bash ./docker-run.sh
```

This will create the docker image and start the container. You will be dropped
into a shell running inside the Docker container. You can build the OS as if you
had installed the dependencies natively.

> The script will create a user inside the docker container that corresponds to the user on
> the host system (same username and user ID).

You can rebuild the image with:

```bash
bash ./docker-run.sh force-build
```

To exit the container, just type `exit` to terminate the shell.

## Build without running

To just build the OS invoke the `run.py` script (in the kernel directory) with
the `-n` parameter (no-run flag).

```bash
python3 kernel/run.py -n
```

If you want to run the build in a docker container, run `bash
./scripts/docker-run.sh` beforehand. The source directory tree will be mounted
in the docker container in `/source`.
