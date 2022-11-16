# LevelDB

And, yet another key--value  store written in C, but this one will also exercise
the file-system (unlike and [memcached](./Memcached.html) or
[Redis](./Redis.html)).

## Automated integration test

The easiest way to run LevelDB on nrk, is to invoke the integration test
directly:

```bash
cd kernel
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_leveldb_benchmark
```

This test will run the db-bench binary for LevelDB which runs various benchmarks
directly in the LevelDB process. Our test is configured to create a database
with 50k entries and a value size of 64 KiB, and then perform 100k random
lookups. The benchmark is repeated while increasing the amount of cores/threads.

## Launch dbbench manually

An example invocation to launch the db-bench binary directly through `run.py`:

```bash
python3 run.py --kfeatures test-userspace-smp \
    --cmd "log=info init=dbbench.bin initargs=28 appcmd=\'--threads=28 --benchmarks=fillseq,readrandom --reads=100000 --num=50000 --value_size=65535\'" \
    --nic virtio --mods rkapps --ufeatures rkapps:leveldb-bench \
    --release --qemu-cores 28 --qemu-nodes 2 --qemu-memory 81920 \
    --qemu-affinity --qemu-prealloc
```

## dbbench example output

Running dbbench should ideally print an output similar to this:

```log
LevelDB:    version 1.18
Keys:       16 bytes each
Values:     100 bytes each (50 bytes after compression)
Entries:    1000000
RawSize:    110.6 MB (estimated)
FileSize:   62.9 MB (estimated)
WARNING: Snappy compression is not enabled
------------------------------------------------
fillseq      :       1.810 micros/op;   61.1 MB/s
fillsync     :       0.000 micros/op;    inf MB/s (1000 ops)
fillrandom   :       1.350 micros/op;   81.9 MB/s
overwrite    :       2.620 micros/op;   42.2 MB/s
readrandom   :       0.000 micros/op; (1000000 of 1000000 found)
readrandom   :      10.440 micros/op; (1000000 of 1000000 found)
readseq      :       0.206 micros/op;  537.4 MB/s
readreverse  :       0.364 micros/op;  303.7 MB/s
compact      :   60000.000 micros/op;
readrandom   :       2.100 micros/op; (1000000 of 1000000 found)
readseq      :       0.190 micros/op;  582.1 MB/s
readreverse  :       0.301 micros/op;  367.7 MB/s
fill100K     :     390.000 micros/op;  244.6 MB/s (1000 ops)
crc32c       :       5.234 micros/op;  746.3 MB/s (4K per op)
snappycomp   :       0.000 micros/op; (snappy failure)
snappyuncomp :       0.000 micros/op; (snappy failure)
acquireload  :       0.000 micros/op; (each op is 1000 loads)
```

## Build steps

Some special handling is currently encoded in the build-process. This is
necessary because dbbench is a C++ program and C++ uses libunwind. However, we
have a conflict here because Rust also uses libunwind and this leads to
duplicate symbols because [vibrio](../userspace/Vibrio.html) and the NetBSD C++
toolchain provide it (the non-hacky solution would probably be to always use the
vibrio provided unwind symbols).

Implications:

* We have a `-L${RUMPRUN_SYSROOT}/../../obj-amd64-nrk/lib/libunwind/` hack in
  the LevelDB Makefile (`$CXX` variable)
* We pass `-Wl,-allow-multiple-definition` to `rumprun-bake` since unwind
  symbols are now defined twice (vibrio and NetBSD unwind lib)

See code in `usr/rkapps/build.rs` which adds flag for this case.

If you'll ever find yourself in a situation where you need to build LevelDB
manually, (most likely not necessary except when debugging build), you can use
the following steps:

```bash
cd nrk/target/x86_64-nrk-none/<release | debug>/build/rkapps-$HASH/out/leveldb
export PATH=`realpath ../../../rumpkernel-$HASH/out/rumprun/bin`:$PATH

RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make clean
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make -j 12 TARGET_OS=NetBSD
RUMPBAKE_ENV="-Wl,-allow-multiple-definition" RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd rumprun-bake nrk_generic ../../../../dbbench.bin bin/db_bench
```

> You might also want to delete the `rm -rf build` and `rm -rf litl` lines in the clean target of the Makefile if you want to call clean to recompile modified sources.

## Run LevelDB on the rumprun unikernel

Build unikernel:

```bash
git clone https://github.com/rumpkernel/rumprun.git
cd rumprun
./build-rr.sh hw -- -F CFLAGS='-w'
. "/PATH/TO/config-PATH.sh"
```

Build LevelDB:

```bash
# Packages install
git clone https://github.com/gz/librettos-packages
cd librettos-packages/leveldb

RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make clean
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make -j 12
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd rumprun-bake hw_virtio dbbench.bin bin/db_bench
```

Run it in a VM:

```bash
rm data.img
mkfs.ext2 data.img 512M
rumprun kvm -i -M 1024 -g '-nographic -display curses' -b data.img,/data -e TEST_TMPDIR=/data dbbench.bin
```
