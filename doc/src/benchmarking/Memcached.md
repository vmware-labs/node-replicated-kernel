# Benchmarking Memcached

Yet another key--value store written in C, but this one is multi-threaded.

## memcached server on nrk

Launch the server binary:

```bash
cd kernel
python3 run.py  \
    --kfeatures test-userspace-smp \
    --cmd 'log=info testbinary=memcached.bin' \
    --nic virtio \
    --mods rkapps \
    --qemu-settings='-m 1024M' \
    --ufeatures 'rkapps:memcached' \
    --release \
    --qemu-cores 4 \
    --verbose
```

As usual make sure `dhcpd` is running on the host:

```bash
cd kernel
sudo service apparmor teardown
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

## Load generator

- `-B`: Binary protocol
- `-S 1S`: Dump statistics every second

```bash
./clients/memaslap -s 172.31.0.10:11211 -B -S 1s
```

Defaults with this set-up are:

- 8 client threads with concurrency of 128 sockets
- 1000000 requests
- set proportion: set_prop=0.10
- get proportion: get_prop=0.90

