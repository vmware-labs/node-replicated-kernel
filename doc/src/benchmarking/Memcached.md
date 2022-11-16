# Benchmarking Memcached

Yet another key--value store written in C, but compared to [Redis](./Redis.html)
this one is multi-threaded.

## Automated integration test

The easiest way to run memcached on nrk, is to invoke the integration test
directly:

```bash
cd kernel
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_memcached_benchmark
```

This test will spawn memcached on one, two and four threads and measure
throughput and latency with
[memaslap](./Memcached.html#memaslap-load-generator).

## Launch memcached manually

Start the server binary on the VM instance:

```bash
cd kernel
python3 run.py  \
    --kfeatures test-userspace-smp \
    --cmd 'log=info init=memcached.bin' \
    --nic virtio \
    --mods rkapps \
    --qemu-settings='-m 1024M' \
    --ufeatures 'rkapps:memcached' \
    --release \
    --qemu-cores 4 \
    --verbose
```

As usual, make sure `dhcpd` is running on the host:

```bash
cd kernel
sudo service apparmor teardown
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

Start the load-generater on the host:

```bash
memaslap -s 172.31.0.10 -t 10s -S 10s
```

## memaslap: Load generator

memaslap measures throughput and latency of a memcached instance. You can invoke
it like this:

```bash
memaslap -s 172.31.0.10:11211 -B -S 1s
```

Explanation of arguments:

- `-B`: Use the binary protocol (faster than the ASCII variant)
- `-S 1s`: Dump statistics every X seconds

The other defaults arguments the tool assumes are:

- 8 client threads with concurrency of 128 sockets
- 1000000 requests
- SET proportion: 10%
- GET proportion: 90%

> Unfortunately, the memaslap binary does not come with standard ubuntu
> packages. Follow the [steps in the CI
> guide](../configuration/CI.html#install-memaslap) to install it from sources.
