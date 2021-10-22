# Using `run.py`

The `kernel/run.py` script provides a simple way to build, deploy and run the
system in various settings and configuration. For a complete set of parameters
and config options refer to the `run.py --help` instructions.

As an example, the following invocation

```bash
python3 run.py --kfeatures test-userspace --cmd='log=info init=redis.bin' --mods rkapps init --ufeatures rkapps:redis --machine qemu --qemu-settings='-m 1024M' --qemu-cores 2
```

will

- compile the kernel with Cargo feature `test-userspace`
- pass the kernel the command-line arguments `log=info init=redis.bin` on
  start-up (sets logging to info and starts redis.bin for testing)
- Compile two user-space modules `rkapps` (with cargo feature redis) and `init`
  (with no features)
- Deploy and run the compiled system on `qemu` with 1024 MiB of memory and 2
  cores allocated to the VM

If Docker is used as build environment, it is necessary to first compile the
system with the required features inside the Docker container:
```bash
python3 run.py --kfeatures test-userspace --mods rkapps init --ufeatures rkapps:redis -n
```
Afterwards, the aforementioned command can be used to run NRK outside the
Docker container with the given configuration. The `run.py` script will
recognize that the system has already been build and will directly start
`qemu`.

Sometimes it's helpful to know what commands are actually executed by `run.py`.
For example to figure out what the exact qemu command line invocation was. In
that case, `--verbose` can be supplied.

Depending on the underlying system configuration NRK may abort because a
connection to the local network can not be established. In this case, the
following steps can help to resolve this issue:
1. Disable AppArmor. Detailed instructions can be found
   [here](../configuration/CI.md#disable-apparmor).
1. Manually start the DHCP server immediately after NRK has started:
   ```bash
   sudo dhcpd -f -d tap0 --no-pid -cf ./kernel/tests/dhcpd.conf
   ```

## Baremetal execution

The `kernel/run.py` script supports execution on baremetal machines with
the `--machine` argument:

```bash
python3 run.py --machine b1542 --verbose --cmd "log=info"
```

This invocation will try to run nrk on the machine described by a
`b1542.toml` config file.

A TOML file for a machine has the following format:

```toml
[server]
# A name for the server we're trying to boot
name = "b1542"
# The hostname, where to reach the server
hostname = "b1542.test.com"
# The type of the machine
type = "skylake2x"
# An arbitrary command to set-up the PXE boot enviroment for the machine
# This often involves creating a hardlink of a file with a MAC address
# of the machine and pointing it to some pxe boot directory
pre-boot-cmd = "./pxeboot-configure.sh -m E4-43-4B-1B-C5-DC -d /home/gz/pxe"

# run.py support only booting machines that have an idrac management console:
[idrac]
# How to reach the ilo/iDRAC interface of the machine
hostname = "b1542-ilo.test.com"
# Login information for iDRAC
username = "user"
password = "pass"
# Serial console which we'll read from
console = "com2"
# Which iDRAC version we're dealing with (currently unused)
idrac-version = "3"
# Typical time until machine is booted
boot-timeout = 320

[deploy]
# Server where binaries are deployed for booting with iPXE
hostname = "ipxe-server.test.com"
username = "user"
ssh-pubkey = "~/.ssh/id_rsa"
# Where to deploy kernel and user binaries
ipxe-deploy = "/home/gz/public_html/"
```

An iPXE environment that the machine will boot from needs to be set-up. The iPXE
bootloader should be compiled with UEFI and ELF support for running with nrk.

> Note that the current support for bare-metal execution is currently limited to
> DELL machines with an iDRAC management console (needed to reboot the server).
> Ideally, redfish or SNMP support will be added in the future.

### Compiling the iPXE bootloader

TBD.

##  Discover CXL devices in Linux with Qemu

This document aims to list out steps to discover CXL type 3 devices inside the Linux kernel. Since there is no hardware available, the only way to achieve that is through Qemu emulation. Unfortunately, even the Qemu mainstream branch does not support these devices, so the tutorial uses a custom version of Qemu that supports CXL type 3 devices.

### Build custom Qemu version

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

### Build custom Linux Kernel
Next, download the latest kernel version and build an image from the source. 

```bash
cd ~/cxl
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
make defconfig
```

`defconfig` generates default configuration values and stores them in the `.config` file. The kernel requires some special configuration changes to handle these devices. Only a few of these configuration flags are present in the `.config` file, so do not worry if you cannot find all these flags.

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

### Run Qemu with CXL related parameters

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

> Press `ctrl+a` and `c` to exit kernel and then press `q` to exit Qemu.

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

#### References
- [Booting a custom linux kernel in Qemu](http://nickdesaulniers.github.io/blog/2018/10/24/booting-a-custom-linux-kernel-in-qemu-and-debugging-it-with-gdb/)
- [CXL 2.0 support in Linux](https://lwn.net/Articles/846061/)
- [CXL 2.0 + Linux + Qemu](https://linuxplumbersconf.org/event/11/contributions/906/attachments/743/1399/LPC2021%20-%20CXL.pdf)