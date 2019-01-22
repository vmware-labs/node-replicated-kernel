#!/bin/bash
set -ex
BESPIN_TARGET=x86_64-bespin

export PATH=`pwd`/../binutils-2.30.90/bin:$PATH
if [ -x "$(command -v x86_64-elf-ld)" ] ; then
    # On non-Linux system we should use the cross-compiled linker from binutils
    export CARGO_TARGET_X86_64_BESPIN_LINKER=x86_64-elf-ld
    OBJCOPY=x86_64-elf-objcopy
else
    OBJCOPY=objcopy
fi

BESPIN_TARGET=x86_64-bespin RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build --target=$BESPIN_TARGET "$@"

cp ../target/$BESPIN_TARGET/debug/bespin kernel
$OBJCOPY ../target/$BESPIN_TARGET/debug/bespin -F elf32-i386 mbkernel

if [ -z ${NORUN+x} ]; then
    set +e
    cat /proc/modules | grep kvm_intel
    if [ $? -eq 0 ]; then
    KVM_ARG='-enable-kvm -cpu host,migratable=no,+invtsc,+tsc'
    else
    KVM_ARG='-cpu qemu64'
    fi
    qemu-system-x86_64 $KVM_ARG -m 1024 -d int -smp 1 -kernel ./mbkernel -initrd kernel -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04 -append "debug"
    QEMU_EXIT=$?
    set +ex
    # qemu will do exit((val << 1) | 1);
    BESPIN_EXIT=$(($QEMU_EXIT >> 1))
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
fi