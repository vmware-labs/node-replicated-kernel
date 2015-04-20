#!/usr/bin/env bash
qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -d int -smp 1  -kernel build-x86_64/x86_64/sbin/kernel -nographic
#-initrd 'init'
#-enable-kvm -cpu host
#-machine pc-q35-1.7 -cpu Haswell,+x2apic