#!/usr/bin/env bash
qemu-system-x86_64 -enable-kvm -cpu host -d int -smp 1  -kernel build-x86_64/x86_64/sbin/kernel -initrd 'cp' -nographic
#-enable-kvm -cpu host
#-machine pc-q35-1.7 -cpu Haswell,+x2apic