# Use RDMA support in QEMU

> **tldr:** The `-pvrdma` option in `run.py` will enable RDMA support in QEMU.
> However, you'll manually have to run `rdmacm-mux` and unload the Mellanox
> modules at the moment.

QEMU has support for `pvrdma` (a para-virtual RDMA driver) which integrates with
physical cards (like Mellanox). In order to use it (aside from the
`--enable-rdma` flag and `sudo make rdmacm-mux` during building), the following
steps are necessary:

Install Mellanox drivers (or any other native drivers for your RDMA card):

```bash
wget https://content.mellanox.com/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
tar zxvf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64
./mlnxofedinstall --all
```

Before running the rdmacm-mux make sure that both ib_cm and rdma_cm kernel
modules aren't loaded, otherwise the rdmacm-mux service will fail to start:

```bash
sudo rmmod ib_ipoib
sudo rmmod rdma_cm
sudo rmmod ib_cm
```

Start the QEMU `racadm-mux` utility (before launching a qemu VM that uses
pvrdma):

```bash
./rdmacm-mux -d mlx5_0 -p 0
```
