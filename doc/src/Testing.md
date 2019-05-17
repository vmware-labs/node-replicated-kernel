# Testing

* Describe test framework


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