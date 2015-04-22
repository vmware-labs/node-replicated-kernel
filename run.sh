#!/usr/bin/env bash
qemu-system-x86_64 -m 1024 -d int -smp 1  -kernel build-x86_64/x86_64/sbin/kernel -initrd 'build-x86_64/x86_64/sbin/init' -nographic
#-initrd 'init'
#-enable-kvm -cpu host
#-machine pc-q35-1.7 -cpu Haswell,+x2apic