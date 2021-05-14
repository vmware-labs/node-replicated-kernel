# Debugging

Unfortunately currently the debugging facilities are quite limited. Use
`printf`-style debugging, logging and staring at code...

Here are a few tips:

- Change the log-level of the kernel to info, debug, or even trace: `python3 run.py --cmd='log=info'`
- Change the log-level of the user-space libOS in virbio (search for `Level::`)
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

The typical workflow to figure out what's going on is:

1. Generally speaking look for the instruction pointer (rip which is `0x534a39`
   in our example).
2. If the instruction pointer (and rsp and rbp) is below kernel base, we were
   probably in user-space when the failure happened (you can also determine it
   by looking at cs/ss but it's easier to tell from the other registers
   usually).
3. Determine exactly the error happened. To do this, we need to find the right
   binary which was running. Those are usually located in
   `target/x86_64-uefi/<release|debug>/esp/<binary>`.
4. Use `addr2line -e <path to binary> <rip>` to see where the error happened.
5. Sometimes `addr2line` doesn't find anything, it's good to check with objdump
   which also gives more context: `objdump -S --disassemble --demangle=rustc
   target/x86_64-uefi/<release|debug>/esp/<binary> | less`
6. The function that gets reported might not be useful (e.g., if things fail in
   `memcpy`). In this case, look for addresses that could be return addresses on
   the stack dump and check them too (e.g., `0x534829` looks suspiciously like a
   return address).
7. If all this fails, something went wrong in a bad way, maybe best to go back
   to printf debugging.

> Always find the first occurence of a failure in the log. Because our
> backtracing code is not very robust, it still quite often triggers cascading
> failures which are not necessarily relevant.