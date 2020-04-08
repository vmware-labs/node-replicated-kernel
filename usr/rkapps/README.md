# rkapps

A wrapper to easily build applications already ported to run on top of rumpkernel for bespin
(i.e., the following repo <https://github.com/rumpkernel/rumprun-packages>)

If we want to invoke a build manually:

```bash
cd target/x86_64-bespin-none/debug/build/rkapps-$HASH/out/redis
export RUMPRUN_TOOLCHAIN_TUPLE=x86_64-rumprun-netbsd
export PATH=`realpath ../../../rumpkernel-$HASH/out/rumprun/bin`:$PATH
make
rumprun-bake bespin_generic redis.out ./bin/redis-server
```
