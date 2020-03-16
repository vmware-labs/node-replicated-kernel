# Testing

* Describe test framework

## Using `run.py`

The `kernel/run.py` script provides a simple way to build, deploy and run the system in various settings and configuration.
For a complete set of parameters and config options refer to the `run.py --help` instructions.

As an example, the following invocation

```bash
python3 run.py --kfeatures test-userspace --cmd='log=info testbinary=redis.bin' --mods rkapps init --ufeatures rkapps:redis --machine qemu --qemu-settings='-m 1024M' --qemu-cores 2
```

will

* compile the kernel with Cargo feature `test-userspace`
* pass the kernel the command-line arguments `log=info testbinary=redis.bin` on start-up (sets logging to info and starts redis.bin for testing)
* Compile two user-space modules `rkapps` (with cargo feature redis) and `init` (with no features)
* Deploy and run the compiled system on `qemu` with 1024 MiB of memory and 2 cores allocated to the VM

## Writing an integration test (for the kernel)

1. Modify `kernel/Cargo.toml` to add a feature (under `[features]`) for the test name.
2. Add a new `xmain` function and test implementation in it to `kernel/src/integration_main.rs` with the used feature name as an annotation.
3. Add a runner function to `kernel/tests/integration-test.rs` that builds the kernel with the cargo feature and runs it.

## Real Hardware

Build produces an uefi.img FAT32 file that can be loaded on real hardware.

Settings on iDRAC
COM2 or COM1 should work

ssh `<idrac ip>`
console com2

Ctrl+\ to exit


Boot controls:
Set to Virtual Floppy

Map virtual media: Select ISO file, attach uefi.img

Then reboot

## Creating an Ubuntu VM (for comparisons)

This is how we create the `ubuntu-testing.img` disk in using the ubuntu-minimal installer:

```bash
wget http://archive.ubuntu.com/ubuntu/dists/bionic/main/installer-amd64/current/images/netboot/mini.iso
qemu-img create -f vmdk -o size=20G ubuntu-testing.img
qemu-system-x86_64 -M 2048 --smp 2 --cpu host -drive mini.iso,device=cdrom -drive ubuntu-testing.img
# Follow installer instructions
```

Afterwards the image can be booted using

```bash
kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img
```

To enable serial output, edit the grub configuration (/etc/default/grub) as follows

```
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_TERMINAL='serial console'
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
```

Following which you must run update-grub to update the menu entries.
From now on boot the VM using:

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic
```

### Redis benchmarking steps (on Linux)

Once the VM is created the following steps are taken to install redis on the guest:

```bash
sudo apt install vim git build-essential libjemalloc1 libjemalloc-dev net-tools
git clone https://github.com/antirez/redis.git
cd redis
git checkout 3.0.6
make
```

To have the same benchmarks conditions as bespin (e.g., use a tap device) launch the VM like this:

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic -net nic,model=e1000,netdev=n0 -netdev tap,id=n0,script=no,ifname=tap0
```

On the guest execute:

```bash
cd redis/src
rm dump.rdb && ./redis-server
```

On the host execute:

```bash
# Launch a DHCP server (can reuse bespin config)
cd bespin/kernel
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf

# Execute redis-benchmark
sudo apt-get install redis-tools
redis-benchmark -h 172.31.0.10 -t get,set,ping
```

Should yield output similar to this:

```log
====== PING_INLINE ======
  100000 requests completed in 1.83 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

83.84% <= 1 milliseconds
99.31% <= 2 milliseconds
99.90% <= 3 milliseconds
99.98% <= 4 milliseconds
100.00% <= 4 milliseconds
54585.15 requests per second

====== PING_BULK ======
  100000 requests completed in 1.92 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

79.65% <= 1 milliseconds
98.92% <= 2 milliseconds
99.89% <= 3 milliseconds
100.00% <= 4 milliseconds
100.00% <= 4 milliseconds
51975.05 requests per second

====== SET ======
  100000 requests completed in 1.94 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

78.46% <= 1 milliseconds
98.93% <= 2 milliseconds
99.92% <= 3 milliseconds
100.00% <= 3 milliseconds
51572.98 requests per second

====== GET ======
  100000 requests completed in 1.93 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1

77.14% <= 1 milliseconds
98.79% <= 2 milliseconds
99.93% <= 3 milliseconds
100.00% <= 3 milliseconds
51813.47 requests per second
```

## Redis benchmarking (default rump-unikernel)

Install the toolchain

```bash
# Rumprun install
./build-rr.sh hw -- -F CFLAGS='-w'
. "/root/rumprun/./obj-amd64-hw/config-PATH.sh"
```

Build an application

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
# Run using virtio (leads to ~100k PING)
rumprun kvm -i -M 256 -I if,vioif,'-net tap,script=no,ifname=tap0'  -g '-curses'  -W if,inet,dhcp  -b images/data.iso,/data -- redis.bin
# Run using e1000 (leads to ~30k PING)
rumprun kvm -i -M 256 -I if,wm,'-net tap,ifname=tap0'  -g '-curses -serial -net nic,model=e1000'  -W if,inet,dhcp  -b images/data.iso,/data -- redis.bin
```

Run the benchmark

```bash
redis-benchmark -h 172.31.0.10
```
