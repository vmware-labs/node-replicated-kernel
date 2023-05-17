# Environment

This chapter contains various notes on configuration and setup of the host
system (Linux), and the hypervisor (QEMU) to use either pass-through or emulate
various technologies for the nrkernel and develop for it.

## Install QEMU from sources

Make sure the QEMU version for the account is is >= 6 . The following steps can
be used to build it from scratch, if it the Ubuntu release has a lesser version
in the package repository.

First, make sure to uncomment all #deb-src lines in /etc/apt/sources.list if not
already uncommented. Then, run the following commands:

```bash
sudo apt update
sudo apt install build-essential libpmem-dev libdaxctl-dev ninja-build
apt source qemu
sudo apt build-dep qemu
wget https://download.qemu.org/qemu-6.0.0.tar.xz
tar xvJf qemu-6.0.0.tar.xz
cd qemu-6.0.0
```

If you are planning on running the rackscale NrOS build, you'll need to modify
the ivshmem server code. Open ```contrib/ivshmem-server/ivshmem-server.c```.
Go to the function```ivshmem_server_ftruncate```. Replace it with:
```c
static int
ivshmem_server_ftruncate(int fd, uint64_t shmsize)
{
    int ret;
    struct stat mapstat;

    /* align shmsize to next power of 2 */
    shmsize = pow2ceil(shmsize);

    if (fstat(fd, &mapstat) != -1 && mapstat.st_size == shmsize) {
        return 0;
    }

    /*
     * This is a do-while loop in case
     * shmsize > IVSHMEM_SERVER_MAX_HUGEPAGE_SIZE
     */
    do {
        ret = ftruncate64(fd, shmsize);
        if (ret == 0) {
            return ret;
        }
        shmsize *= 2;
    } while (shmsize <= IVSHMEM_SERVER_MAX_HUGEPAGE_SIZE);

    return -1;
}
```

```bash
./configure --enable-rdma --enable-libpmem
make -j 28
sudo make -j28 install
sudo make rdmacm-mux

# Check version (should be >=6.0.0)
qemu-system-x86_64 --version
```

You can also add `--enable-debug` to the configure script which will add debug
information (useful for source information when stepping through qemu code in
gdb).

Note that if you are only updating the ```ivshmem-server```, it may not install
correctly with the ```make install``` command above. Instead, you can use
```which ivshmem-server``` to find the current location and then overwrite it
with ```qemu-6.0.0/build/contrib/ivshmem-server/ivshmem-server```. 
