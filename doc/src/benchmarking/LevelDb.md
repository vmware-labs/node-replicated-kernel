# LevelDB

## Rump

Build unikernel:

```bash
git clone https://github.com/rumpkernel/rumprun.git
cd rumprun
./build-rr.sh hw -- -F CFLAGS='-w'
. "/PATH/TO/config-PATH.sh"
```

Build leveldb:

```bash
# Packages install
git clone https://github.com/gz/librettos-packages
cd librettos-packages/leveldb

RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make clean
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make -j 12
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd rumprun-bake hw_virtio dbbench.bin bin/db_bench
```

Run it:

```bash
rm data.img
mkfs.ext2 data.img 512M
rumprun kvm -i -M 1024 -g '-nographic -display curses' -b data.img,/data -e TEST_TMPDIR=/data dbbench.bin
```
