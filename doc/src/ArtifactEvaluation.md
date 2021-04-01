# Artifact Evaluation

Thank you for your time and picking our paper for the artifact evaluation.

This file contains the steps to run experiments used in our OSDI'21 paper:
NrOS: Effective Replication and Sharing in an Operating System.

> All the experiments run smoothly on the c6420 CloudLab machine. There might be
> some issues if one tries to run the experiments on some other machine with a
> different configuration.

## Reserve a cloudlab machine

Please follow the given steps to reserve a machine to run the experiments.

  1. Setup an account on [CloudLab](https://www.cloudlab.us), if not already present.
  2. Log in to [CloudLab](https://www.cloudlab.us/login.php) and setup a [password-less](https://docs.cloudlab.us/users.html#%28part._ssh-access) ssh key.
  3. Start an experiment by clicking on `Experiments` on top left of the webpage.
  4. Use the node type [c6420](https://docs.cloudlab.us/hardware.html), and setup the node with the Ubuntu 20.04 disk image.

## Download the code and setup the environment

Download the source code `.tar.gz` file using [this
link](https://drive.google.com/file/d/1Yy4DPG_jUOqspS1fCNMpZOXI4bdnzRSf/view?usp=sharing).

```bash
cd $HOME
tar zxvf bespin-24ce69c.tar.gz
cd bespin_ae
bash setup.sh
```

## Configure the lab machine

Add password-less sudo capability for your user (scripts require it):

```bash
sudo visudo
# Add the following line at the bottom of the file:
$YOUR_USERNAME_HERE  ALL=(ALL) NOPASSWD: ALL
```

Add yourself to the KVM group:

```bash
sudo adduser $USER kvm
```

Disable apparmor, an annoying security feature that blocks the DHCP server from
starting during testing. You can also set-up a rule to allowing this but it's
easiest to just get rid of it on the test machine:

```bash
sudo systemctl stop apparmor
sudo systemctl disable apparmor
sudo apt remove --assume-yes --purge apparmor
```

Unfortunately, for apparmor and kvm group changes to take effect, we need to
reboot:

```bash
sudo reboot
```

## Do a test run

> Note: Most of our benchmarks takes a while to finish, so it is better to now
> switch to a tmux session, or increase the session timeout to avoid
> disconnects.

To check if the environment is setup properly, run

```bash
source $HOME/.cargo/env
cd bespin_ae/kernel
python3 ./run.py --release
```

The script downloads needed crates, compiles the OS and runs a basic test (the
`run.py` step can take a few minutes).

If everything worked, you should see the following last lines in your output:

```log
[DEBUG] - init: Initialized logging
[DEBUG] - init: Done with init tests, if we came here probably everything is good.
[SUCCESS]
```

## Figure 3: NR-FS vs. tmpfs

Please follow the given steps to reproduce Figure 3 in the paper.

### Nr-FS results

To execute the benchmark, run:

```bash
RUST_TEST_THREADS=1 cargo test --features mlnrfs --test integration-test -- s06_fxmark_bench --nocapture
```

The command runs all NR-FS microbenchmarks and stores the results in a CSV file
`fxmark_benchmark.csv`.

### Linux tmpfs results

If desired you can also re-generate the `tmpfs` result on Linux:

```bash
cd $HOME
git clone https://github.com/gz/vmops-bench.git -b fs-bench
cd vmops-bench
bash scripts/ci.bash
```

The above command runs the benchmark and generates the results in a csv-file
`fsops_benchmark.csv`.

### Plot the figure

TODO - To generate the final graph use the plot script...

## Figure 4: LevelDB

Figure 4 in the paper compares LevelDB workload performance for NR-FS and
Linux-tmpfs.

### NrOS

To run the LevelDB benchmark on NrOS run:

```bash
cd $HOME/bespin_ae/kernel
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_leveldb_benchmark --nocapture
```

The command runs the benchmark and generates the results in a csv-file
`leveldb_benchmark.csv`.

### Linux

To run the LevelDB benchmark on Linux follow the steps below. Please clone the
leveldb repository in a different path than NrOS.

```bash
cd $HOME
git clone https://github.com/amytai/leveldb.git -b bespin-linux-lock
cd leveldb
bash run.sh
```

The above commands run the benchmarks and generate the results in a csv-file
`linux_leveldb.csv`.

### Plot the figure

TODO - To generate the final graph use the plot script...

## NR-VMem Benchmarks

Paper figure 5 and 6.