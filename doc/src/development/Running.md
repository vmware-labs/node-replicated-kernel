# Using `run.py`

The `kernel/run.py` script provides a simple way to build, deploy and run the
system in various settings and configuration. For a complete set of parameters
and config options refer to the `run.py --help` instructions.

As an example, the following invocation

```bash
python3 run.py --kfeatures test-userspace --cmd='log=info testbinary=redis.bin' --mods rkapps init --ufeatures rkapps:redis --machine qemu --qemu-settings='-m 1024M' --qemu-cores 2
```

will

- compile the kernel with Cargo feature `test-userspace`
- pass the kernel the command-line arguments `log=info testbinary=redis.bin` on
  start-up (sets logging to info and starts redis.bin for testing)
- Compile two user-space modules `rkapps` (with cargo feature redis) and `init`
  (with no features)
- Deploy and run the compiled system on `qemu` with 1024 MiB of memory and 2
  cores allocated to the VM

Sometimes it's helpful to know what commands are actually execute by `run.py`.
For example to figure out what the exact qemu command line arguments were. In
that case `--verbose` can be supplied.