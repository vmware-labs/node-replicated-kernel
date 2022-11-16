# Benchmarking Redis

Redis is a simple, single-threaded key--value store written in C. It is a useful
test to measure single-threaded performance of the system.

## Automated integration tests

The easiest way to run redis on nrk, is to invoke the redis integration tests
directly:

* `s05_redis_smoke` will spawn nrk with a redis instance, connect to it using
  `nc` and issue a few commands to test basic functionality.
* `s10_redis_benchmark_virtio` and `s10_redis_benchmark_e1000` will spawn nrk
  with a redis instance and launch the `redis-benchmark` CLI tool on the host
  for benchmarking. The results obtained by redis-benchmark are parsed and
  written into `redis_benchmark.csv`. The `virtio` and `e1000` suffix indicate
  which network driver is used.

```bash
cd kernel
# Runs both _virtio and _e1000 redis benchmark tests
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_redis_benchmark
```

## Launch redis manually

You can also do the steps that the integration test does manually. We start a
DHCP server first. The `apparmor teardown` is necessary if you don't have a
security policy that allows the use of a `dhcpd.conf` at this location.

```bash
cd kernel
sudo service apparmor teardown
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

Next run the redis server in nrk (exchange the nic parameter with `virtio` to
use the virtio NIC):

```bash
python3 run.py \
  --kfeatures test-userspace \
  --nic e1000 \
  --cmd "log=info init=redis.bin" \
  --mods rkapps \
  --ufeatures "rkapps:redis" \
  --qemu-settings="-m 1024M"
```

Finally, execute the redis-benchmark on the host.

```bash
redis-benchmark -h 172.31.0.10 -n 10000000 -p 6379 -t get,set -P 29
```

You should see an output similar to this:

```log
====== SET ======
  10000000 requests completed in 10.29 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

0.31% <= 1 milliseconds
98.53% <= 2 milliseconds
99.89% <= 3 milliseconds
100.00% <= 4 milliseconds
100.00% <= 4 milliseconds
972100.75 requests per second

====== GET ======
  10000000 requests completed in 19.97 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

0.14% <= 1 milliseconds
6.35% <= 2 milliseconds
77.66% <= 3 milliseconds
94.62% <= 4 milliseconds
97.04% <= 5 milliseconds
99.35% <= 6 milliseconds
99.76% <= 7 milliseconds
99.94% <= 8 milliseconds
99.99% <= 9 milliseconds
99.99% <= 10 milliseconds
100.00% <= 11 milliseconds
100.00% <= 11 milliseconds
500726.03 requests per second
```


## redis-benchmark

`redis-benchmark` is a closed-loop benchmarking tool that ships with redis. You
can get it on Ubuntu by installing the `redis-tools` package:

```bash
sudo apt-get install redis-tools
```

Example invocation:

```bash
redis-benchmark -h 172.31.0.10 -t set,ping
```

For maximal throughput, use pipelining (`-P`), and the virtio network driver:

```bash
redis-benchmark -h 172.31.0.10 -n 10000000 -p 6379 -t get,set -P 29
```

## Redis on Linux

> You'll need a Linux VM image, see the [Compare against
> Linux](./Baselines.html#compare-against-linux) section for steps on how to
> create one.

Before starting the VM we can re-use the DHCP server config in
`nrk/kernel/tests` to start a DHCP server on the host that configures the
network of the guest VM:

```bash
# Launch a DHCP server (can reuse nrk config)
cd nrk/kernel
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

Next, start the VM. To have the same benchmarks conditions as nrk (e.g., use a
tap device) launch the VM like this (select either e1000 or virtio, generally
virtio will perform better than emulated e1000):

*e1000 NIC*:

```bash
qemu-system-x86_64 \
  --enable-kvm -m 2048 -k en-us --smp 2 \
  -boot d ubuntu-testing.img -nographic \
  -net nic,model=e1000,netdev=n0 \
  -netdev tap,id=n0,script=no,ifname=tap0
```

*virtio NIC*:

```bash
qemu-system-x86_64 \
  --enable-kvm -m 2048 -k en-us --smp 2 \
  -boot d ubuntu-testing.img -nographic \
  -net nic,model=virtio,netdev=n0 \
  -netdev tap,id=n0,script=no,ifname=tap0
```

Inside the Linux VM use the following steps to install redis:

```bash
sudo apt install vim git build-essential libjemalloc1 libjemalloc-dev net-tools
git clone https://github.com/antirez/redis.git
cd redis
git checkout 3.0.6
make
```

Finally, start redis:

```bash
cd redis/src
rm dump.rdb && ./redis-server
```

Some approximate numbers to expect on a Linux VM and Server CPUs:

e1000, no pipeline:

* SET 50k req/s
* GET 50k req/s

virtio, `-P 29`:

* SET 1.8M req/s
* GET 2.0M req/s

## Redis on the rumprun unikernel

Install the toolchain:

```bash
git clone https://github.com/rumpkernel/rumprun.git rumprun
cd rumprun
# Rumprun install
git submodule update --init
./build-rr.sh hw -- -F CFLAGS='-w'
. "/root/rumprun/./obj-amd64-hw/config-PATH.sh"
```

Build the redis unikernel:

```bash
# Packages install
git clone https://github.com/gz/rumprun-packages.git
cd rumprun-packages

cp config.mk.dist config.mk
vim config.mk

cd redis
make -j8
rumprun-bake hw_generic redis.bin bin/redis-server
```

Run the unikernel

```bash
# Run using virtio
rumprun kvm -i -M 256 -I if,vioif,'-net tap,script=no,ifname=tap0'  -g '-curses'  -W if,inet,dhcp  -b images/data.iso,/data -- redis.bin
# Run using e1000
rumprun kvm -i -M 256 -I if,wm,'-net tap,ifname=tap0'  -g '-curses -serial -net nic,model=e1000'  -W if,inet,dhcp  -b images/data.iso,/data -- redis.bin
```

Run the benchmark

```bash
redis-benchmark -h 172.31.0.10
```

Approximate numbers to expect:

* virtio: PING ~100k req/s
* e1000 PING ~30k req/s
