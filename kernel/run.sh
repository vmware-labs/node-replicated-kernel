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

set +e
cat /proc/modules  | grep kvm_intel
if [ $? -eq 0 ]; then
KVM_ARG='-enable-kvm'
else
KVM_ARG=''
fi

qemu-system-x86_64 $KVM_ARG -m 2048 -d int -smp 1 -kernel ./mbkernel -initrd kernel -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04
QEMU_EXIT=$?
# qemu will do exit((val << 1) | 1);
BESPIN_EXIT=$(($QEMU_EXIT >> 1))
echo ""
case "$BESPIN_EXIT" in
    0)
    MESSAGE="[SUCCESS]"
    ;;
    1)
    MESSAGE="[FAIL] ReturnFromMain: main() function returned to arch_indepdendent part."
    ;;
    2)
    MESSAGE="[FAIL] Encountered kernel panic."
    ;;
    3)
    MESSAGE="[FAIL] Encountered OOM."
    ;;
    4)
    MESSAGE="[FAIL] Encountered unexpected Interrupt."
    ;;
    5)
    MESSAGE="[FAIL] General Protection Fault."
    ;;
    6)
    MESSAGE="[FAIL] Unexpected Page Fault."
    ;;
    *)
    MESSAGE="[FAIL] Kernel exited with unknown error status $BESPIN_EXIT... Update the script!"
    ;;
esac
echo $MESSAGE
exit $BESPIN_EXIT
