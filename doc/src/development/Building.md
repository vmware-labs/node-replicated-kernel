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
dependencies.

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

## Install QEMU from sources

> Note that normally this step won't be necessary and you can use the QEMU
> distribution that comes with Ubuntu.

Sometimes it's necessary to run QEMU from the latest sources, to debug an issue
or to use a new feature not yet available in the Ubuntu deb release. The
following steps can be used to build it from scratch:

First, make sure to uncomment all #deb-src lines in /etc/apt/sources.list if not
already uncommented. Then, run the following commands:

```bash
sudo apt update
sudo apt install build-essential
apt source qemu
sudo apt build-dep qemu
wget https://download.qemu.org/qemu-5.0.0.tar.xz
tar xvJf qemu-5.0.0.tar.xz
cd qemu-5.0.0
./configure --enable-rdma
make -j 28
sudo make -j28 install
sudo make rdmacm-mux
```

You can also add `--enable-debug` to the configure script which will add debug
information (useful for source information when stepping through qemu code in
gdb).

### Use RDMA support in QEMU

QEMU has support for `pvrdma` (a para-virtual RDMA driver) which integrates with
physical cards (like Mellanox). In order to use it (aside from the
`--enable-rdma` flag and `sudo make rdmacm-mux` during building), the following
steps are necessary:

Install Mellanox drivers (or any other native drivers for your RDMA card):

```bash
wget https://content.mellanox.com/ofed/MLNX_OFED-5.2-2.2.0.0/MLNX_OFED_LINUX-5.2-2.2.0.0-ubuntu20.04-x86_64.tgz
tar zxvf MLNX_OFED_LINUX-5.2-2.2.0.0-ubuntu20.04-x86_64.tgz
./mlnxofedinstall --all
```

Before running `rdmacm-mux` make sure that both ib_cm and rdma_cm kernel modules
aren't loaded, otherwise the rdmacm-mux service will fail to start:

```bash
sudo rmmod ib_ipoib ib_cm rdma_cm rmmod ib_cm rdma_ucm rdma_cm
```

Start the QEMU `racadm-mux` utility (before launching a qemu VM that uses
pvrdma):

```bash
sudo ./rdmacm-mux -d mlx5_0 -p 0
```

Unfortunately the tool doesn't have good error reporting (yet). But it is
supposed to *not* exit/return immediately and keep running. If you find that it
will exit immediately it might help to use `sudo strace <cmd>` to see if some
system call failed.


If you're not running qemu as root you might need permission to access
`/var/run/rdmacm-mux-mlx5_0-0`:

```
sudo chmod a+rwx /var/run/rdmacm-mux-mlx5_0-0
```

You will need to make sure that a `bridge.conf` file exists, otherwise qemu
aborts with this error:  `qemu-system-x86_64: bridge helper failed`. To fix it,
create the file with `allow all` inside it:

```
sudo mkdir -p /usr/local/etc/qemu
sudo bash -c "echo 'allow all' >> /usr/local/etc/qemu/bridge.conf"
sudo chmod u+s /usr/local/libexec/qemu-bridge-helper
```

If everything is set-up correctly, you should be able to run the pvrdma smoke
test:

```bash
cd kernel
python3 run.py --kfeatures integration-test test-pvrdma-smoke --nic vmxnet3 --pvrdma
```
