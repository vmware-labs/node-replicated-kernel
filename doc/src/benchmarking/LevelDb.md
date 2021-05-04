# LevelDB

## NRK

```log
threads=1
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

threads=4
Keys:       16 bytes each
Values:     100 bytes each (50 bytes after compression)
Entries:    500000
RawSize:    55.3 MB (estimated)
FileSize:   31.5 MB (estimated)
WARNING: Snappy compression is not enabled
------------------------------------------------
fillseq      :      64.285 micros/op;    6.0 MB/s
fillsync     :      40.000 micros/op;   11.1 MB/s (500 ops)
fillrandom   :      41.865 micros/op;    8.8 MB/s
overwrite    :      46.465 micros/op;    7.8 MB/s
readrandom   :       6.915 micros/op; (500000 of 500000 found)
readrandom   :       2.690 micros/op; (500000 of 500000 found)
readseq      :       0.127 micros/op; 1670.8 MB/s
readreverse  :       0.112 micros/op;  987.3 MB/s
compact      : 1360000.000 micros/op;
readrandom   :       1.770 micros/op; (500000 of 500000 found)
readseq      :       0.046 micros/op; 2413.4 MB/s
readreverse  :       0.071 micros/op; 1551.5 MB/s
crc32c       :       0.000 micros/op;    inf MB/s (4K per op)
snappycomp   :    2500.000 micros/op; (snappy failure)
snappyuncomp :   20000.000 micros/op; (snappy failure)
acquireload  :       0.000 micros/op; (each op is 1000 loads)
```

### Build

Some special handling is currently necessary since it's a C++ program:
We have our own unwind handling (do nothing) in virbio.a
It should really be it's own unwind.a library.

Implications:

* We have a `-L${RUMPRUN_SYSROOT}/../../obj-amd64-nrk/lib/libunwind/` hack in the LevelDB Makefile (`$CXX` variable)
* We pass `-Wl,-allow-multiple-definition` to rumprun-bake since unwind symbols are now defined twice (vibrio and NetBSD unwind lib)

#### Manual build steps

Most likely unneeded except for debugging build:

```bash
cd /home/gz/workspace/nrk/target/x86_64-nrk-none/release/build/rkapps-3b5fae9f3a9314d8/out/leveldb
export PATH=`realpath ../../../rumpkernel-b6392f675947fae3/out/rumprun/bin`:$PATH
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make clean
RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make -j 12
RUMPBAKE_ENV="-Wl,-allow-multiple-definition"  RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd rumprun-bake nrk_generic ../../../../dbbench.bin bin/db_bench
```

### Run

```bash
cd nrk/kernel
"python3" "run.py" "--kfeatures" "test-userspace-smp" "--cmd" "log=info testbinary=dbbench.bin testcmd=1" "--mods" "rkapps" "--nic" "virtio" "--ufeatures" "rkapps:leveldb-bench" "--release" "--qemu-cores" "1" "--qemu-nodes" "1" "--qemu-memory" "8192" --qemu-monitor --verbose --qemu-debug
```

## Linux

Expected output (db_bench):

```bash
./db_bench --threads=1
LevelDB:    version 1.18
Date:       Fri May 15 03:05:04 2020
CPU:        12 * AMD Ryzen 5 3600X 6-Core Processor
CPUCache:   512 KB
Keys:       16 bytes each
Values:     100 bytes each (50 bytes after compression)
Entries:    1000000
RawSize:    110.6 MB (estimated)
FileSize:   62.9 MB (estimated)
WARNING: Snappy compression is not enabled
------------------------------------------------
fillseq      :       1.675 micros/op;   66.1 MB/s
fillsync     :    1139.001 micros/op;    0.1 MB/s (1000 ops)
fillrandom   :       3.213 micros/op;   34.4 MB/s
overwrite    :       4.747 micros/op;   23.3 MB/s
readrandom   :       2.400 micros/op; (1000000 of 1000000 found)
readrandom   :       1.797 micros/op; (1000000 of 1000000 found)
readseq      :       0.154 micros/op;  719.6 MB/s
readreverse  :       0.277 micros/op;  399.5 MB/s
compact      :  639480.000 micros/op;
readrandom   :       1.214 micros/op; (1000000 of 1000000 found)
readseq      :       0.136 micros/op;  815.3 MB/s
readreverse  :       0.237 micros/op;  467.5 MB/s
fill100K     :     991.805 micros/op;   96.2 MB/s (1000 ops)
crc32c       :       2.588 micros/op; 1509.3 MB/s (4K per op)
snappycomp   :    4276.000 micros/op; (snappy failure)
snappyuncomp :    4183.000 micros/op; (snappy failure)
acquireload  :       0.323 micros/op; (each op is 1000 loads)

./db_bench --threads=4
LevelDB:    version 1.18
Date:       Fri May 15 02:01:20 2020
CPU:        12 * AMD Ryzen 5 3600X 6-Core Processor
CPUCache:   512 KB
Keys:       16 bytes each
Values:     100 bytes each (50 bytes after compression)
Entries:    1000000
RawSize:    110.6 MB (estimated)
FileSize:   62.9 MB (estimated)
WARNING: Snappy compression is not enabled
------------------------------------------------
fillseq      :      16.771 micros/op;   26.3 MB/s
fillsync     :    2113.892 micros/op;    0.2 MB/s (1000 ops)
fillrandom   :      21.929 micros/op;   20.2 MB/s
overwrite    :      23.718 micros/op;   18.6 MB/s
readrandom   :       3.782 micros/op; (1000000 of 1000000 found)
readrandom   :       2.936 micros/op; (1000000 of 1000000 found)
readseq      :       0.180 micros/op; 2158.1 MB/s
readreverse  :       0.342 micros/op; 1078.6 MB/s
compact      : 7415773.000 micros/op;
readrandom   :       2.441 micros/op; (1000000 of 1000000 found)
readseq      :       0.161 micros/op; 2402.1 MB/s
readreverse  :       0.263 micros/op; 1522.0 MB/s
fill100K     :   11044.394 micros/op;   34.5 MB/s (1000 ops)
crc32c       :       2.645 micros/op; 5862.9 MB/s (4K per op)
snappycomp   :    2592.750 micros/op; (snappy failure)
snappyuncomp :   15306.000 micros/op; (snappy failure)
acquireload  :       0.338 micros/op; (each op is 1000 loads)
```

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
