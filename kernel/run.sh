#!/bin/bash
set -ex

ld -n --gc-sections -Tsrc/arch/x86_64/link.ld -o kernel ../target/bespin/debug/libbespin.a
objcopy kernel -F elf32-i386 mbkernel
qemu-system-x86_64 -m 2048 -d int -smp 1 -kernel ./mbkernel -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04