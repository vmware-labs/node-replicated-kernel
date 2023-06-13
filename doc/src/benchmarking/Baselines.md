# Baseline Operating Systems

Contains steps to get other operating systems compiled and running for
comparison purposes.

## Compare against Linux

To get an idea if nrk is competitive with Linux performance we can create a
Linux VM by creating an image. The following steps create an
`ubuntu-testing.img` disk-image by using the ubuntu-minimal installer:

```bash
wget http://archive.ubuntu.com/ubuntu/dists/bionic/main/installer-amd64/current/images/netboot/mini.iso
qemu-img create -f vmdk -o size=20G ubuntu-testing.img
kvm -m 2048 -k en-us --smp 2 --cpu host -cdrom mini.iso -hdd ubuntu-testing.img
# Follow installer instructions
```

Afterwards the image can be booted using `kvm`:

```bash
kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img
```

### Switch to serial output

One step that makes life easier is to enable to serial input/output. So we don't
have to use a graphical QEMU interface. To enable serial, edit the grub
configuration (/etc/default/grub) as follows in the VM:

```cfg
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_TERMINAL='serial console'
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
```

Then you must run `update-grub` to update the menu entries. From now on, you can
boot the VM using (not the `-nographic` option):

```bash
qemu-system-x86_64 --enable-kvm -m 2048 -k en-us --smp 2 -boot d ubuntu-testing.img -nographic
```

## Compare against Barrelfish

TBD.

## Compare against sv6

To clone & build the code (needs an older compiler version):

```bash
git clone https://github.com/aclements/sv6.git
sudo apt-get install gcc-4.8 g++-4.8
CXX=g++-4.8 CC=gcc-4.8 make
```

Update `param.h`:

```bash
QEMU       ?= qemu-system-x86_64 -enable-kvm
QEMUSMP    ?= 56
QEMUMEM    ?= 24000
```

Run:

```bash
CXX=g++-4.8 CC=gcc-4.8 make qemu`
```

# Rackscale

One of the baselines for rackscale is NrOS. To run the rackscale benchmarks with corresponding NrOS baslines, run them with ```--feature baseline```.
