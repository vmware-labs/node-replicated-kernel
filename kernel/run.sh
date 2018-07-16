#!/bin/bash
set -ex
export PATH=../binutils-2.30.90/bin:$PATH

RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build --target=bespin

if [ -x "$(command -v x86_64-elf-ld)" ] ; then
    x86_64-elf-ld -n --gc-sections -Tsrc/arch/x86_64/link.ld -o kernel ../target/bespin/debug/libbespin.a
    x86_64-elf-objcopy kernel -F elf32-i386 mbkernel
else
    ld -n --gc-sections -Tsrc/arch/x86_64/link.ld -o kernel ../target/bespin/debug/libbespin.a
    objcopy kernel -F elf32-i386 mbkernel
fi

qemu-system-x86_64 -m 1024 -d int -smp 1 -kernel ./mbkernel -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04