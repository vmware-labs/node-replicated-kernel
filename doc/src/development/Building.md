# Building

There are two sets of dependencies required for the development process: build and run
dependencies.


## Dependencies Short Version

To install both build and run dependencies execute `setup.sh` in the root of the repository.
The script will install all required OS packages, install Rust using `rustup` and configures
the Rust toolchain accordingly.


## Build Dependencies

The build dependencies can be divided into four categories
 * python3 to execute the build scripts
 * build environment
 * Rump Kernel app dependencies
 * Rust (nightly) for compiling the OS

See `scripts/generic-setup.sh` function `install_build_dependencies` for details.

We require Rust `nightly` toolchain and the `rust-src` to build the OS.
(See `bootstrap_rust` in `scripts/generic-setup.sh`)
Lastly, we require a few Rust crates to be installed.

## Using Docker

We provide scripts to create a docker image containing all build dependencies. To create the
image execute the following command in the `/scripts` directory.

```
$ bash ./docker-run.sh
```

This will create the docker image and runs the container. You will be dropped into a shell running
inside the Docker container. You can build the OS as if you had installed the dependencies
natively.

Note: the script will create a user inside the docker container that corresponds to the user on
the host system (same username and user ID).

You can rebuild the image with:

```
$ bash ./docker-run.sh force-build
```

To exit the container, just type `exit` to terminate the shell.

## Building

To build the OS invoke the run script with the `-n` parameter indicating that running it is not
wanted (no-run flag).

```
$ python3 kernel/run.py -n
```

If you want to run the build in a docker container, run `bash ./scripts/docker-run.sh` beforehand.
The source directory tree will be mounted in the docker container at `/source`.