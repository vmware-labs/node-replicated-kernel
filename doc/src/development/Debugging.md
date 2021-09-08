# Debugging

Unfortunately currently the debugging facilities are quite limited. Use
`printf`-style debugging, logging and staring at code...

Here are a few tips:

- Change the log-level of the kernel to info, debug, or even trace: `python3 run.py --cmd='log=info'`
- Change the log-level of the user-space libOS in vibrio (search for `Level::`)
- Make sure the [Tests](./Testing.md) run (to see if something broke).

## Figuring out why things failed

Maybe you'll encounter failures, for example like this one:

```log
[IRQ] GENERAL PROTECTION FAULT: From Any memory reference and other protection checks.
No error!
Instruction Pointer: 0x534a39
ExceptionArguments { vec = 0xd exception = 0x0 rip = 0x534a39, cs = 0x23 rflags = 0x13206 rsp = 0x5210400928 ss = 0x1b }
Register State:
Some(SaveArea

rax =                0x0 rbx =                0x0 rcx =                0x0 rdx =                0x0
rsi =                0x0 rdi =       0x5210400a50 rbp =       0x5210400958 rsp =       0x5210400928
r8  =                0x2 r9  =       0x5202044c00 r10 =                0x3 r11 =           0x28927a
r12 =       0x520e266810 r13 =           0x7d8ac0 r14 =           0x6aaaf9 r15 =           0x686680
rip =           0x534a39 rflags = FLAGS_RF | FLAGS_IOPL1 | FLAGS_IOPL2 | FLAGS_IOPL3 | FLAGS_IF | FLAGS_PF | FLAGS_A1)
stack[0] = 0x5210400958
stack[1] = 0x53c7fd
stack[2] = 0x0
stack[3] = 0x0
stack[4] = 0x0
stack[5] = 0x0
stack[6] = 0x52104009b8
stack[7] = 0x534829
stack[8] = 0x5210400a50
stack[9] = 0x5210400a50
stack[10] = 0x0
stack[11] = 0x268
```

The typical workflow to figure out what went wrong:

1. Generally, look for the instruction pointer (`rip` which is `0x534a39` in our
   example).
1. If the instruction pointer (and `rsp` and `rbp`) is below kernel base, we
   were probably in user-space when the failure happened (you can also determine
   it by looking at cs/ss but it's easier to tell from the other registers).
1. Determine exactly where the error happened. To do this, we need to find the
   right binary which was running. Those are usually located in
   `target/x86_64-uefi/<release|debug>/esp/<binary>`.
1. Use `addr2line -e <path to binary> <rip>` to see where the error happened.
1. If the failure was in kernel space, make sure you adjust any addresses by
   substracting the PIE offset where the kernel binary was executing in the
   virtual space. Look for the following line `INFO: Kernel loaded at address:
   0x4000bd573000`, it's printed by the bootloader early during the boot
   process. Substract the printed number to get the correct offset in the ELF
   file.
1. Sometimes `addr2line` doesn't find anything, it's good to check with objdump,
   which also gives more context: `objdump -S --disassemble --demangle=rustc
   target/x86_64-uefi/<release|debug>/esp/<binary> | less`
1. The function that gets reported might not be useful (e.g., if things fail in
   `memcpy`). In this case, look for addresses that could be return addresses on
   the stack dump and check them too (e.g., `0x534829` looks suspiciously like a
   return address).
1. If all this fails, something went wrong in a bad way, maybe best to go back
   to printf debugging.

> Always find the first occurrence of a failure in the serial log. Because our
> backtracing code is not very robust, it still quite often triggers cascading
> failures which are not necessarily relevant.

## Debugging rumpkernel/NetBSD components

nrk user-space links with a rather large (NetBSD) code-base. When things go
wrong somewhere in there, it's sometimes helpful to temporarily change or get
some debug output directly in the C code.

You can edit that code-base directly since it gets checked out and built in the
target directory. For example, to edit the `rump_init` function, open the file
in the `rumpkern` folder of the NetBSD source here:
`target/x86_64-nrk-none/release/build/rumpkernel-$HASH/out/src-netbsd/sys/rump/librump/rumpkern/rump.c`

Make sure to identify the correct $HASH that is used for the build if you find
that there are multiple `rumpkernel-*` directories in the build dir, otherwise
your changes won't take effect.

After you're done with edits, you can manually invoke the build, and launch the
OS again.

```bash
cd target/x86_64-nrk-none/release/build/rumpkernel-$HASH/out
./build-rr.sh -j24 nrk -- -F "CFLAGS=-w"
# Invoke run.py again...
```

> If you change the compiler/rustc version, do a clean build, or delete the
> target directory your changes might be overridden as the sources exist only
> inside the build directory (`target`). It's a good idea to save changes
> somewhere for safekeeping if they are important.

## Debugging in QEMU/KVM

If the system ends up in a dead-lock, you might be able to get a sense of where
things went south by asking qemu. Deadlocks with our kernel design are rare, but
in user-space (thanks to locking APIs) it can definitely happen.

The following steps should help:

1. Add `--qemu-monitor` to the run.py invocation to start the qemu monitor.
1. Connect to the monitor in a new terminal with `telnet 127.0.0.1 55555`.
1. You can use `info registers -a` to get a dump of the current register state
   for all vCPUs or any other command to query the hypervisor state.
1. If you're stuck in some loop, getting a couple register dumps might tell you
   more than invoking `info registers` just once.

When developing drivers that are emulated in qemu, it can be useful to enable
debug prints for the interface in QEMU to see what state the device is in. For
example, to enable debug output for `vmxnet3` in the sources, you can change the
`#undef` statements in `hw/net/vmxnet_debug.h` to `#define` and recompile the
qemu sources (your changes should look similar to this snippet below):

```c
#define VMXNET_DEBUG_CB
#define VMXNET_DEBUG_INTERRUPTS
#define VMXNET_DEBUG_CONFIG
#define VMXNET_DEBUG_RINGS
#define VMXNET_DEBUG_PACKETS
#define VMXNET_DEBUG_SHMEM_ACCESS
```

## Debugging with gdb

NRK provides an implementation for the gdb remote protocol using a separate
serial line for communication.

To use it, start `run.py` with the `--gdb` argument. Once booted, the following
line will appear:

```log
Waiting for a GDB connection on I/O port 0x2f8...
Use `target remote localhost:1234` in gdb session to connect
```

Connect with GDB to the kernel:

```bash
gdb
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
...
```
