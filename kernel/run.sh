#!/bin/bash
set -ex

ld -n --gc-sections -Tsrc/arch/x86_64/link.ld -o kernel ../target/bespin/debug/libbespin.a
objcopy kernel -F elf32-i386 mbkernel
qemu-system-x86_64 -m 1024 -d int -smp 1 -kernel ./mbkernel -nographic