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
  4. Use the node type [c6420](https://docs.cloudlab.us/hardware.html) (by entrying `Optional physical node type` - c6420), and setup the node with the Ubuntu 20.04 disk image.

## Download the code and setup the environment

Download and checkout the sources:

```bash
cd $HOME
git clone https://github.com/vmware-labs/node-replicated-kernel.git nrk
cd nrk
git checkout osdi21-ae-v2
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

> Most likely apparmor is not installed if you're using cloud-lab,
in this case the commands will fail and you can ignore that.

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
cd $HOME/nrk/kernel
python3 ./run.py --release
```

The script downloads needed crates, compiles the OS and runs a basic test (the
`run.py` step can take a few minutes).

If everything worked, you should see the following last lines in your output:

```log
[...]
[DEBUG] - init: Initialized logging
[DEBUG] - init: Done with init tests, if we came here probably everything is good.
[SUCCESS]
```

## Figure 3: NR-FS vs. tmpfs

Please follow the given steps to reproduce Figure 3 in the paper.

### NrFS results

To execute the benchmark, run:

```bash
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_fxmark_bench --nocapture
```

The command runs all NR-FS microbenchmarks and stores the results in a CSV file
`fxmark_benchmark.csv`. This step can take a while (~30-60 min).

If everything worked, you should see an output like this one at the end:

```log
[...]
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32X8XmixX100" "--nic" "e1000" "--mods" "init" "--ufeatures" "fxmark" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "49152" "--qemu-affinity"
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32X12XmixX100" "--nic" "e1000" "--mods" "init" "--ufeatures" "fxmark" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "49152" "--qemu-affinity"
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32X16XmixX100" "--nic" "e1000" "--mods" "init" "--ufeatures" "fxmark" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "49152" "--qemu-affinity"
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 2769.78s
```

### Linux tmpfs results

You can also generate the `tmpfs` result on Linux:

```bash
cd $HOME
git clone https://github.com/gz/vmopsbench
cd vmopsbench
git checkout c011854
bash scripts/run.sh
```

The above command runs the benchmark and writes the results in a csv-file
`fsops_benchmark.csv`.

### Plot Figure 3

All the plot scripts are in a github repository, execute the following to clone it.

```bash
cd $HOME
git clone https://github.com/ankit-iitb/plot-scripts.git
```

To install the required dependencies, run:

```bash
cd $HOME/plot-scripts
sudo apt install python3-pip
pip3 install -r requirements.txt
```

Plot the Figure 3 by running:

```bash
# python3 fsops_plot.py <Linux fsops csv> <NrOS fsops csv>
python3 fsops_plot.py $HOME/vmopsbench/fsops_benchmark.csv $HOME/nrk/kernel/fxmark_benchmark.csv
```

> Arguments given in the plot scripts assume that the result files were not moved after the run.
Please use the argument order given in the comment, if csv files were moved for some reason.

## Figure 4: LevelDB

Figure 4 in the paper compares LevelDB workload performance for NR-FS and
Linux-tmpfs.

### LevelDB on NrOS

To run the LevelDB benchmark on NrOS execute:

```bash
cd $HOME/nrk/kernel
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_leveldb_benchmark --nocapture
```

This step will take ~15-20min. If everything worked, you should see an output like this one at the end:

```log
[...]
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info init=dbbench.bin initargs=32 appcmd=\'--threads=32 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535\'" "--nic" "virtio" "--mods" "rkapps" "--ufeatures" "rkapps:leveldb-bench" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "81920" "--qemu-affinity" "--qemu-prealloc"
readrandom   : done: 3200000,  949492.348 ops/sec; (100000 of 50000 found)
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 738.67s
```

The command runs benchmarks and stores the results in a CSV file:
`leveldb_benchmark.csv`.

### LevelDB on Linux

To run the LevelDB benchmark on Linux follow the steps below. Please clone the
leveldb repository in a different path than NrOS.

```bash
cd $HOME
git clone https://github.com/amytai/leveldb.git
cd leveldb
git checkout 8af5ca6
bash run.sh
```

The above commands run the benchmarks and writes the results in a csv-file
`linux_leveldb.csv`.

### Plot the LevelDB figure

Make sure that steps to download the plot scripts and install required dependencies have already
been performed as explained in [Plot Figure 3](#plot-figure-3) before plotting Figure 4.

Run the following commands to plot the Figure 4.

```bash
cd $HOME/plot-scripts
# python3 leveldb_plot.py <Linux leveldb csv> <NrOS leveldb csv>
python3 leveldb_plot.py $HOME/leveldb/linux_leveldb.csv $HOME/nrk/kernel/leveldb_benchmark.csv
```

## Figure 5 / 6a / 6c

Figure 5 in the paper compares address-space insertion throughput and latency
for NR-VMem with Linux.

### NR-VMem

To run the throughput benchmark (Figure 5) on NrOS execute:

```bash
cd $HOME/nrk/kernel
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_benchmark --nocapture
```

This step will take ~3min. If everything worked, you should see an output like this one at the end:

```log
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32" "--nic" "e1000" "--mods" "init" "--ufeatures" "bench-vmops" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "49152" "--qemu-affinity"
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 118.94s
```

The results will be stored in `vmops_benchmark.csv`.

To run the latency benchmark (Figure 6a) on NrOS execute:

```bash
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_latency_benchmark --nocapture
```

This step will take ~2min. If everything worked, you should see an output like this one at the end:

```log
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32" "--nic" "e1000" "--mods" "init" "--ufeatures" "bench-vmops,latency" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "32768" "--qemu-affinity"
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 106.67s
```

The results will be stored in `vmops_benchmark_latency.csv`.

To run the unmap latency benchmark (Figure 6c) on NrOS execute:

```bash
cd $HOME/nrk/kernel
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_unmaplat_latency_benchmark --nocapture
```

This step will take ~2min. If everything worked, you should see an output like this one at the end:

> Be aware unmap latency numbers might be impacted by the virtual execution of
> NrOS.

```log
Invoke QEMU: "python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info initargs=32" "--nic" "e1000" "--mods" "init" "--ufeatures" "bench-vmops-unmaplat,latency" "--release" "--qemu-cores" "32" "--qemu-nodes" "2" "--qemu-memory" "32768" "--qemu-affinity"
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 97.38s
```

The results will be stored in `vmops_unmaplat_benchmark_latency.csv`.

### Linux VMem

To run the benchmark on Linux follow the steps below.

```bash
cd $HOME/vmopsbench
git checkout master
bash scripts/linux.bash throughput
bash scripts/linux.bash latency
bash scripts/linux-tlb.bash latency
```

The results for Figure 5, 6a, and 6c will be store in:

- Figure 5 in `vmops_linux_maponly-isolated-shared_threads_all_throughput_results.csv`
- Figure 6a in `Linux-Map_latency_percentiles.csv`
- Figure 6c in `Linux-Unmap_latency_percentiles.csv`

### Plot Figure 5 and 6a and 6c

Go to the plot-scripts repository:

```bash
cd $HOME/plot-scripts
```

Plot Figure 5:

```bash
# python3 vmops_throughput_plot.py  <linux vmops csv> <bespin vmops csv>
python3  vmops_throughput_plot.py  $HOME/vmopsbench/vmops_linux_maponly-isolated-shared_threads_all_throughput_results.csv $HOME/nrk/kernel/vmops_benchmark.csv
```

Plot Figure 6a:

```bash
# python3 map_latency_plot.py <linux map-latency csv> <bespin map-latency csv>
python3 map_latency_plot.py $HOME/vmopsbench/Linux-Map_latency_percentiles.csv $HOME/nrk/kernel/vmops_benchmark_latency.csv
```

Plot Figure 6c:

```bash
# python3 mapunmap_latency_plot.py <linux unmap-latency csv> <bespin unmap-latency csv>
python3 mapunmap_latency_plot.py $HOME/vmopsbench/Linux-Unmap_latency_percentiles.csv $HOME/nrk/kernel/vmops_unmaplat_benchmark_latency.csv
```
