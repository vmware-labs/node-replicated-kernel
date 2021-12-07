#  Inter-VM Communication using Shared memory

> **tldr:** Use the `--qemu-ivshmem` and `--qemu-shmem-path` option in `run.py`
> to enable cross-VM shared-memory support in QEMU.

This section describes how to use shared memory to communicate between two Qemu
VMs. First, create a shared memory file (with hugepages):

```bash
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/hugepages
sudo mount -t hugetlbfs pagesize=2GB /mnt/huge
sudo chmod 777 /mnt/hugepages
```

Now, use a file on this mount point to create a shared memory file across two
Qemu VMs. For shared memory, Qemu allows two types of configurations:

- Just the shared memory file: `ivshmem-plain`.
- Shared memory plus interrupts: `ivshmem-doorbell`.

We use the plain shared memory configuration as the goal is to share memory
across machines. Add the following parameters to the Qemu command line:

```bash
-object memory-backend-file,size=2G,mem-path=/mnt/hugepages/shmem-file,share=on,id=HMB \
-device ivshmem-plain,memdev=HMB
```

## Discover the shared memory file inside Qemu

Qemu exposes the shared memory file to the kernel by creating a PCI device.
Inside the VM, run the following command to discover to check if the PCI device
is created or not.

```bash
lspci | grep "shared memory"
```
Running lspci should show something like:

```log
00:04.0 RAM memory: Red Hat, Inc. Inter-VM shared memory (rev 01)
```

Use the `lspci` command to know more about the PCI device and BAR registers.

```bash
lspci -s 00:04.0 -nvv
```

This should print the BAR registers related information. The ivshmem PCI device has two to
three BARs (depending on shared memory or interrupt device):

- BAR0 holds device registers (256 Byte MMIO)
- BAR1 holds MSI-X table and PBA (only ivshmem-doorbell)
- BAR2 maps the shared memory object

Since we are using the plain shared memory configuration, the BAR1 is not used.
We only see the BAR0 and BAR2 as Region 0 and Region 1.

```log
00:04.0 0500: 1af4:1110 (rev 01)
	Subsystem: 1af4:1100
	Physical Slot: 4
	Control: I/O+ Mem+ BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap- 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Region 0: Memory at febf1000 (32-bit, non-prefetchable) [size=256]
	Region 2: Memory at 280000000 (64-bit, prefetchable) [size=2G]
```

## Use the shared memory file inside Qemu

If you only need the shared memory part, BAR2 suffices.  This way, you have
access to the shared memory in the guest and can use it as you see fit. Region 2
in `lspci` output tells us that the shared memory is at `280000000` with the
size of `2G`.

Here is a sample C program that writes to the shared memory file.

```bash
#include<stdio.h>
#include<stdint.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/mman.h>

int main() {
	void *baseaddr = (void *) 0x280000000; // BAR2 address
	uint64_t size = 2147483648; // BAR2 size

	int fd = open("/sys/bus/pci/devices/0000:00:04.0/resource2", O_RDWR | O_SYNC);
	void *retaddr = mmap(baseaddr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		printf("mmap failed");
		return 0;
	}

	uint8_t *addr = (uint8_t *)retaddr;
	addr[0] = 0xa;

	munmap(retaddr, size);
	close(fd);
}
```

Compile and run the program (use `sudo` to run).

Perform the similar steps to read the shared memory file in another Qemu VM.
