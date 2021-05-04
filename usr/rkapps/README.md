# rkapps

A wrapper to easily build applications already ported to run on top of rumpkernel for nrk
(uses the following repo <https://github.com/rumpkernel/rumprun-packages>).

Check `build.rs` for steps.

## redis

If we want to invoke a build manually:

```bash
cd redis
cd target/x86_64-nrk-none/debug/build/rkapps-$HASH/out/redis
export RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd
export PATH=`realpath ../../../rumpkernel-$HASH/out/rumprun/bin`:$PATH
make
rumprun-bake nrk_generic redis.out ./bin/redis-server
```

## memcached

```bash
cd "target/x86_64-nrk-none/release/build/rkapps-8a4ead00329ed64e/out/memcached"
PATH=target/x86_64-nrk-none/release/build/rumpkernel-934f79a93edbe559/out/rumprun/bin:$PATH RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd make -j 12
PATH=target/x86_64-nrk-none/release/build/rumpkernel-934f79a93edbe559/out/rumprun/bin:$PATH RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd rumprun-bake nrk_generic ../../../../memcached.bin build/memcached
```
