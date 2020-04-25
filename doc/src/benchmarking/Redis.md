# Benchmarking Redis

Redis is a simple, single-threaded key--value store written in C.

## redis-benchmark

`redis-benchmark` is a closed-loop benchmarking tool that ships with redis. You
can get it through `redis-tools`:

```bash
sudo apt-get install redis-tools
```

When invoked

```bash
redis-benchmark -h 172.31.0.10 -t set,ping
```

For max throughput, use pipelining (`-P`), and the virtio network
driver:

```bash
redis-benchmark -h 172.31.0.10 -n 10000000 -p 6379 -t get,set -P 29
```

Approximate numbers to expect on a Linux VM:

e1000, no pipeline:

* SET 50k req/s
* GET 50k req/s

virtio, `-P 29`:

* SET 1.8M req/s
* GET 2.0M req/s

## Redis server on bespin

To run test the redis performance on bespin, you can either invoke the
redis_benchmark integration test directly:

```bash
cd kernel
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_redis_benchmark
```

The test will automatically launch qemu with bespin/redis and `redis-benchmark`
on the hosts. Results are written into `redis_benchmark.csv`.

You can also do the steps that the integration-test does manually.
We start a DHCP server first. The apparmor teardown is necessary
if you don't have a security policy that allows the use of a
`dhcpd.conf` at this location.

```bash
cd kernel
sudo service apparmor teardown
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

Next run the redis server in bespin:

```bash
"python3" "run.py" "--kfeatures" "test-userspace" "--cmd" "log=info testbinary=redis.bin" "--nic" "e1000" "--mods" "rkapps" "--ufeatures" "rkapps:redis" "--qemu-settings=-m 1024M"
```

Finally execute redis-benchmark from the host.

```bash
redis-benchmark -h 172.31.0.10 -n 10000000 -p 6379 -t get,set -P 29
```

Approximate numbers to expect when using virtio and the invocation from above:

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


## Redis on Linux

In our Linux VM use the following steps to install redis:

```bash
sudo apt install vim git build-essential libjemalloc1 libjemalloc-dev net-tools
git clone https://github.com/antirez/redis.git
cd redis
git checkout 3.0.6
make
```

Before starting the VM we can re-use the DHCP config in `bespin/kernel/tests` to
start a DHCP server on the host that configures the network of the guest VM:

```bash
# Launch a DHCP server (can reuse bespin config)
cd bespin/kernel
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

To have the same benchmarks conditions as bespin (e.g., use a tap device) launch the VM like this
(select either e1000 or virtio, generally virtio will perform better than emulated e1000):

e1000 NIC:

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic -net nic,model=e1000,netdev=n0 -netdev tap,id=n0,script=no,ifname=tap0
```

virtio NIC:

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic -net nic,model=virtio,netdev=n0 -netdev tap,id=n0,script=no,ifname=tap0
```

On the guest execute:

```bash
cd redis/src
rm dump.rdb && ./redis-server
```

## Redis on rumprun

Install the toolchain:

```bash
# Rumprun install
./build-rr.sh hw -- -F CFLAGS='-w'
. "/root/rumprun/./obj-amd64-hw/config-PATH.sh"
```

Build redis unikernel application:

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

Approximate results to expect:

* virtio: PING ~100k req/s
* e1000 PING ~30k req/s