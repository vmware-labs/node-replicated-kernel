# Artifact Evaluation
Thank you for your time and picking our paper for the artifact evaluation.

This file contains the steps to run experiments used in our OSDI'21 paper
(NrOS: Effective Replication and Sharing in an Operating System).

> All the experiments run smoothly on the c6420 CloudLab machine. There might be
some issues if one tries to run the experiments on some other machine with a
different configuration.

## Reserve a machine
Please follow the given steps to reserve a machine to run the experiments.
  1. Setup an account on [CloudLab](https://www.cloudlab.us), if not already present.
  2. Log in to [CloudLab](https://www.cloudlab.us/login.php) and setup a [password-less](https://docs.cloudlab.us/users.html#%28part._ssh-access) ssh key.
  3. Start an experiment by clicking on `Experiments` on top left of the webpage.
  4. Use the node type [c6420](https://docs.cloudlab.us/hardware.html), and setup the node with the Ubuntu 20.04 disk image.

## Checkout the code and setup the environment
```bash
git clone https://github.com/gz/bespin.git
cd bespin
sed -i'' -e 's/git@github.com:/https:\/\/github.com\//' .gitmodules
git submodule init
git submodule update
bash setup.sh
```
To check if the environment is setup properly, run ```bash cd kernel; python3 ./run.py --release```
The script downloads all the needed crates, compiles the OS and runs a basic test.

> Note: Most of our benchmarks takes a while to finish, so it is better to use tmux session or increase
the session timeout to avoid unwanted session closing.

## Microbenchmark: NR-FS vs tmpfs
Please follow the given steps to reproduce Figure 3 in the paper that compares NR-FS and tmpfs for
various read and write filesystem based workloads.

To run the NR-FS benchmarks, go to the kernel directory(`.../bespin/kernel`) and run:
```bash
RUST_TEST_THREADS=1 cargo test --features mlnrfs --test integration-test -- s06_fxmark_bench --nocapture
```
The command runs all the NR-FS microbenchmarks and generates the results in a csv-file `fxmark_benchmark.csv`.

TODO - To run the Linux-tempfs benchmarks...

TODO - To generate the final graph use the plot script...

## LevelDB Benchmark
Figure 4 in the paper compares leveldb read-intensive workload performance for NR-FS and Linux-tmpfs.

To run the LevelDB benchmark on NrOS, go to the kernel directory(`.../bespin/kernel`) and run:
```bash
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_leveldb_benchmark --nocapture
```
The command runs a read-intensive LevelDB benchmark and generates the results in a csv-file `leveldb_benchmark.csv`.

TODO - To run the LevelDB benchmark on Linux...

TODO - To generate the final graph use the plot script...

## NR-VMem Benchmarks
Paper figure 5 and 6