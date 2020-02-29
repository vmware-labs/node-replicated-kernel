# Testing

* Describe test framework

## Using `run.py`

The `kernel/run.py` script provides a simple way to build, deploy and run the system in various settings and configuration.
For a complete set of parameters and config options refer to the `run.py --help` instructions.

As an example, the following invocation
```bash
python3 run.py --kfeatures test-userspace --cmd='log=info testbinary=redis.bin' --mods rkapps init --ufeatures rkapps:redis --machine qemu --qemu-settings='-m 1024M' --qemu-cores 2
```
will
 * compile the kernel with Cargo feature `test-userspace`
 * pass the kernel the command-line arguments `log=info testbinary=redis.bin` on start-up (sets logging to info and starts redis.bin for testing)
 * Compile two user-space modules `rkapps` (with cargo feature redis) and `init` (with no features)
 * Deploy and run the compiled system on `qemu` with 1024 MiB of memory and 2 cores allocated to the VM

## Writing an integration test (for the kernel)

1. Modify `kernel/Cargo.toml` to add a feature (under `[features]`) for the test name.
2. Add a new `xmain` function and test implementation in it to `kernel/src/integration_main.rs` with the used feature name as an annotation.
3. Add a runner function to `kernel/tests/integration-test.rs` that builds the kernel with the cargo feature and runs it.

## Real Hardware

Build produces an uefi.img FAT32 file that can be loaded on real hardware.

Settings on iDRAC
COM2 or COM1 should work

ssh <idrac ip>
console com2

Ctrl+\ to exit


Boot controls:
Set to Virtual Floppy

Map virtual media: Select ISO file, attach uefi.img

Then reboot