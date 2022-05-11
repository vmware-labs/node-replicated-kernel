# Discover CXL devices in Linux with Qemu

This document aims to list out steps to discover CXL type 3 devices inside the
Linux kernel. Since there is no hardware available, the only way to achieve that
is through Qemu emulation. Unfortunately, even the Qemu mainstream branch does
not support these devices, so the tutorial uses a custom version of Qemu that
supports CXL type 3 devices.

## Build custom Qemu version

First, download and build the custom Qemu version on your machine.

```bash
sudo apt install build-essential libpmem-dev libdaxctl-dev ninja-build
cd ~/cxl
git clone https://gitlab.com/bwidawsk/qemu.git
cd qemu
git checkout cxl-2.0v4
./configure --enable-libpmem
make -j 16
```

Check the version:

```bash
./build/qemu-system-x86_64 --version
```

```log
QEMU emulator version 6.0.50 (v6.0.0-930-g18395653c3)
Copyright (c) 2003-2021 Fabrice Bellard and the QEMU Project developers
```

## Build custom Linux Kernel

Next, download the latest kernel version and build an image from the source.

```bash
cd ~/cxl
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
make defconfig
```

`defconfig` generates default configuration values and stores them in the
`.config` file. The kernel requires some special configuration changes to handle
these devices. Only a few of these configuration flags are present in the
`.config` file, so do not worry if you cannot find all these flags.

```bash
CONFIG_ACPI_HMAT=y
CONFIG_ACPI_APEI_PCIEAER=y
CONFIG_ACPI_HOTPLUG_MEMORY=y
CONFIG_MEMORY_HOTPLUG=y
CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE=y
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_CXL_BUS=y
CONFIG_CXL_MEM=y
```

Once the configuration related changes are done, compile the kernel code to the generate the image file.

```bash
make -j 16
cd ~/cxl
```

The image file should be in `linux/arch/x86_64/boot/bzImage`.

## Run Qemu with CXL related parameters

Qemu provides `-kernel` parameter to use the kernel image directly.
Let's try to use that -

```bash
qemu/build/qemu-system-x86_64 -kernel linux/arch/x86_64/boot/bzImage \
 -nographic -append "console=ttyS0" -m 1024 --enable-kvm
```

The kernel runs until it tries to find the root fs; then it crashes.
One easy way to resolve this is to create a ramdisk.

```bash
mkinitramfs -o ramdisk.img
```

> Press `Ctrl+a` and `c` to exit kernel and then press `q` to exit Qemu.

Now, run qemu with the newly created ramdisk:

```bash
qemu/build/qemu-system-x86_64 -kernel linux/arch/x86_64/boot/bzImage -nographic \
    -append "console=ttyS0" -m 1024 -initrd ramdisk.img --enable-kvm
```

The kernel runs properly this time. Now, it is time to add CXL related parameters before running Qemu:

```bash
qemu/build/qemu-system-x86_64 -kernel linux/arch/x86_64/boot/bzImage -nographic \
    -append "console=ttyS0" -initrd ramdisk.img -enable-kvm \
    -m 1024,slots=12,maxmem=16G -M q35,accel=kvm,cxl=on \
    -object memory-backend-file,id=cxl-mem1,share=on,mem-path=cxl-window1,size=512M \
 -object memory-backend-file,id=cxl-label1,share=on,mem-path=cxl-label1,size=1K \
 -object memory-backend-file,id=cxl-label2,share=on,mem-path=cxl-label2,size=1K \
 -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52,uid=0,len-window-base=1,window-base[0]=0x4c00000000,memdev[0]=cxl-mem1 \
 -device cxl-rp,id=rp0,bus=cxl.0,addr=0.0,chassis=0,slot=0,port=0 \
 -device cxl-rp,id=rp1,bus=cxl.0,addr=1.0,chassis=0,slot=1,port=1 \
 -device cxl-type3,bus=rp0,memdev=cxl-mem1,id=cxl-pmem0,size=256M,lsa=cxl-label1 \
 -device cxl-type3,bus=rp1,memdev=cxl-mem1,id=cxl-pmem1,size=256M,lsa=cxl-label2
```

Qemu exposes the CXL devices to the kernel and the kernel discovers these devices.
Verify the devices by running:

```bash
ls /sys/bus/cxl/devices/
```

or

```bash
dmesg | grep '3[45]:00'
```

## References

- [Booting a custom linux kernel in Qemu](http://nickdesaulniers.github.io/blog/2018/10/24/booting-a-custom-linux-kernel-in-qemu-and-debugging-it-with-gdb/)
- [CXL 2.0 support in Linux](https://lwn.net/Articles/846061/)
- [CXL 2.0 + Linux + Qemu](https://linuxplumbersconf.org/event/11/contributions/906/attachments/743/1399/LPC2021%20-%20CXL.pdf)
