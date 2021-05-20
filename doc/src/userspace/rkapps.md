# rkapps

The rkapps directory (in `usr/rkapps`) is an empty project aside from the
`build.rs` file. The build file contains the steps to clone and build a few
different well-known programs (memcached, LevelDB, Redis etc.) that we use to
test user-space and rumprt.

The checked-out program sources and binaries are placed in the following
location as part of your build directory:

```target/x86_64-nrk-none/<debug | release>/build/rkapps-$HASH/out/```

The build for these programs can be a bit hard to understand. The following
steps happen:

1. Clone the packages repo which has build instructions for different POSIX
   programs running on rumpkernels.
2. For each application that we want to build (enabled/disabled by feature
   flags): Run `make` in the respective directory. This will compile the
   application with the appropriate rumpkernel toolchain. The toolchain be found
   in a similar path inside the build directory:
   `target/x86_64-nrk-none/<debug | release>/build/rumpkernel-$HASH`
3. Linking binaries with vibrio which provides the low-level runtime for
   rumpkernels.


> For more information on how to run rkapps applications, refer to the
> [Benchmarking](..//benchmarking/Benchmarking.html) section.