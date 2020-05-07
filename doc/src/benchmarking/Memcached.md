# Benchmarking Memcached

Yet another key--value store written in C, but this one is multi-threaded.

## memcached server on bespin

Launch the server binary:

```bash
cd kernel
python3 run.py  \
    --kfeatures test-userspace \
    --cmd 'log=info testbinary=memcached.bin' \
    --nic virtio \
    --mods rkapps \
    --qemu-settings='-m 1024M' \
    --ufeatures 'rkapps:memcached' \
    --release \
    --verbose
```

As usual make sure `dhcpd` is running on the host:

```bash
cd kernel
sudo service apparmor teardown
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```
