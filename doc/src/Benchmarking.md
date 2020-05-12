# Benchmarking

We can run several POSIX applications through the rump interface provided by NetBSD.
This chapter provides notes and pointers on how to set-up certain applications
for benchmarking.

## Creating an Ubuntu VM (for comparison)

To get a first idea if bespin is competitive with Linux performance we can typically create
a Linux VM first by creating an image.
This is how we create a `ubuntu-testing.img` disk-image by using the ubuntu-minimal installer:

```bash
wget http://archive.ubuntu.com/ubuntu/dists/bionic/main/installer-amd64/current/images/netboot/mini.iso
qemu-img create -f vmdk -o size=20G ubuntu-testing.img
kvm -m 2048 -k en-us --smp 2 --cpu host -cdrom mini.iso -hdd ubuntu-testing.img
# Follow installer instructions
```

Afterwards the image can be booted using:

```bash
kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img
```

### Switch to serial output

One first thing that makes life easier is to switch to serial input. So we don't have
to use a graphical QEMU interface. To enable serial output, edit the grub
configuration (/etc/default/grub) as follows in the VM:

```cfg
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_TERMINAL='serial console'
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
```

Then you must run `update-grub` to update the menu entries.
From now on you can boot the VM using (not the `-nographic` option):

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic
```

## Ping micro-benchmark

One first, simple check is to use ping (on the host) to test the network stack
latency. Adaptive `ping -A`, flooding `ping -f` are both good modes for that.

```log
e1000:
64 bytes from 172.31.0.10: icmp_seq=1 ttl=64 time=0.259 ms
64 bytes from 172.31.0.10: icmp_seq=2 ttl=64 time=0.245 ms
64 bytes from 172.31.0.10: icmp_seq=3 ttl=64 time=0.267 ms
64 bytes from 172.31.0.10: icmp_seq=4 ttl=64 time=0.200 ms

virtio:
64 bytes from 172.31.0.10: icmp_seq=4 ttl=64 time=0.420 ms
64 bytes from 172.31.0.10: icmp_seq=5 ttl=64 time=0.206 ms
64 bytes from 172.31.0.10: icmp_seq=6 ttl=64 time=0.292 ms
64 bytes from 172.31.0.10: icmp_seq=7 ttl=64 time=0.196 ms
```

## Compare against sv6

Clone & Build:

```bash
git clone https://github.com/aclements/sv6.git
sudo apt-get install gcc-4.8 g++-4.8
CXX=g++-4.8 CC=gcc-4.8 make
```

Update param.h:

```bash
QEMU       ?= qemu-system-x86_64 -enable-kvm
QEMUSMP    ?= 56
QEMUMEM    ?= 24000
```

Run:

```bash
CXX=g++-4.8 CC=gcc-4.8 make qemu`
```
