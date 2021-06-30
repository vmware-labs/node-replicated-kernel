# Continuous integration (CI)

We run tests using the github-actions infrastructure. The following steps are
necessary to set-up a new runner machine (and connect a github repo to it).

Steps to add a new CI machine:

  1. [Install github-runner software on a new test machine](#install-github-runner-software-on-a-new-test-machine)
  1. [Give access to the benchmark repository](#give-access-to-the-benchmark-repository)
  1. [Configure software for the `github-runner` account](#configure-software-for-the-github-runner-account)
  1. [Disable AppArmor](#disable-apparmor)
  1. [Install a recent QEMU](#install-a-recent-qemu)
  1. [Do a test-run](#do-a-test-run)

## Install github-runner software on a new test machine

Create a github-runner user first:

```bash
sudo useradd github-runner -m -s /bin/zsh
```

Add sudo capability for github-runner:

```bash
visudo
# github-runner  ALL=(ALL) NOPASSWD: ALL
```

For added security we use the binaries of [Rust's action
runner](https://github.com/rust-lang/gha-runner/). For more information, check
[this PR](https://github.com/actions/runner/pull/783).

Other than that, follow the steps listed under `Settings -> Actions -> Runner ->
Add runner`. Just make sure to replace the curl URL with the latest release from
the link above. For the latest version at the time of writing the documentation:

```bash
cd $HOME
mkdir actions-runner && cd actions-runner
curl -o actions-runner-linux-x64-2.278.0.tar.gz -L https://github.com/rust-lang/gha-runner/releases/download/v2.278.0-rust1/actions-runner-linux-x64-2.27
8.0-rust1.tar.gz
./config.sh --url << repo url >> --token << token from web ui >>
```

When asked for labels, make sure to give it a machine specific tag. For example,
we currenly use the following labels `skylake2x`, `skylake4x`, `cascadelake2x`,
`ryzen5` to indicate different machine type and the number of sockets/NUMA
nodes. Machines with identical hardware should have the same tag to allow
parallel test execution.

Finally, launch the runner by permitting only jobs originating from push requests:

```bash
RUST_WHITELISTED_EVENT_NAME=push ./run.sh
```

TBD: Run as systemd service

## Give access to the benchmark repository

Benchmark results are uploaded automatically to git.

Generate a key for accessing the repository or use an existing key on the
github-runner account. Also add the user to the KVM group. Adding yourself to
the KVM group requires a logout/reboot which we do in later steps.

```bash
sudo su github-runner
sudo adduser github-runner kvm
ssh-keygen
```

Then, add the pub key (`.ssh/id_rsa.pub`) to the github CI account.

## Configure software for the github runner account

Install necessary software for use by the runner:

```bash
git clone git@github.com:vmware-labs/node-replicated-kernel.git nrk
cd nrk/
bash setup.sh
source $HOME/.cargo/env
```

## Install a recent qemu

Make sure the QEMU version for the runner account is is >= 5:

```bash
cd $HOME
sudo apt update
sudo apt install build-essential
sudo apt build-dep qemu

wget https://download.qemu.org/qemu-5.0.0.tar.xz
tar xvJf qemu-5.0.0.tar.xz

cd qemu-5.0.0
./configure --enable-rdma
make -j 28
sudo make -j28 install

# Check version (should be 5.0.0)
qemu-system-x86_64 --version
```

## Install memaslap

The memcached benchmark uses the `memaslap` binary that comes with
`libmemcached` but is not included in the Ubuntu libmemcached-tools deb package.
You'll have to install it manually from the sources:

```bash
cd $HOME
sudo apt-get build-dep libmemcached-tools
wget https://launchpad.net/libmemcached/1.0/1.0.18/+download/libmemcached-1.0.18.tar.gz
tar zxvf libmemcached-1.0.18.tar.gz

cd libmemcached-1.0.18/
LDFLAGS='-lpthread' CXXFLAGS='-fpermissive' CFLAGS='-Wno-errors -fpermissive' ./configure --enable-memaslap --with-pthread=yes
make -j12
sudo make install
sudo ldconfig

which memaslap
```

## Disable AppArmor

An annoying security feature that blocks our DHCP server from starting for
testing. You can set-up a rule for allowing this but it's easiest to just get
rid of it on the CI machine:

```bash
sudo systemctl stop apparmor
sudo systemctl disable apparmor
sudo apt remove --assume-yes --purge apparmor
# Unfortunately for apparmor and kvm group changes to take effect, we need to reboot:
sudo reboot
```

## Do a test-run

After the reboot, verify that the nrk tests pass (this will take a while, but if
it works CI will likely succeed too):

```bash
# Init submodules if not done so already:
cd nrk
git submodule update --init
source $HOME/.cargo/env

cd kernel
RUST_TEST_THREADS=1 cargo test --features smoke -- --nocapture
```

## Repository settings

If the repo is migrated to a new location, the following settings should be mirrored:

1. Under Settings -> Secrets: Add secret `WEBSITE_DEPLOY_SSH_KEY` which contains
   a key to push the generated documentation to the correct website repository.
1. Under Settings -> Options: Disable "Allow merge commits"
1. Under Settings -> Branches: Add branch protection for `master`, enable the following settings:
   - Require pull request reviews before merging
   - Dismiss stale pull request approvals when new commits are pushed
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
   - Require linear history
