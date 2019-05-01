#!/bin/bash
set -ex


# ARG_OPTIONAL_SINGLE([features],[f],[Rust features to enable.])
# ARG_OPTIONAL_SINGLE([log],[l],[Arguments for logger.])
# ARG_OPTIONAL_BOOLEAN([release],[r],[Do a release build.])
# ARG_OPTIONAL_BOOLEAN([norun],[n],[Only build, don't run.])
# ARG_HELP([Bespin runner script])
# ARGBASH_GO()
# m4_ignore([

die()
{
	local _ret=$2
	test -n "$_ret" || _ret=1
	test "$_PRINT_HELP" = yes && print_help >&2
	echo "$1" >&2
	exit ${_ret}
}

begins_with_short_option()
{
	local first_option all_short_options
	all_short_options='flrnh'
	first_option="${1:0:1}"
	test "$all_short_options" = "${all_short_options/$first_option/}" && return 1 || return 0
}

# THE DEFAULTS INITIALIZATION - OPTIONALS
_arg_features=
_arg_log=
_arg_release="off"
_arg_norun="off"

print_help ()
{
	printf '%s\n' "Bespin runner script"
	printf 'Usage: %s [-f|--features <arg>] [-l|--log <arg>] [-r|--(no-)release] [-n|--(no-)norun] [-h|--help]\n' "$0"
	printf '\t%s\n' "-f,--features: Rust features to enable. (no default)"
	printf '\t%s\n' "-l,--log: Arguments for logger. (no default)"
	printf '\t%s\n' "-r,--release,--no-release: Do a release build. (off by default)"
	printf '\t%s\n' "-n,--norun,--no-norun: Only build, don't run. (off by default)"
	printf '\t%s\n' "-h,--help: Prints help"
}

parse_commandline ()
{
	while test $# -gt 0
	do
		_key="$1"
		case "$_key" in
			-f|--features)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
				_arg_features="$2"
				shift
				;;
			--features=*)
				_arg_features="${_key##--features=}"
				;;
			-f*)
				_arg_features="${_key##-f}"
				;;
			-l|--log)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
				_arg_log="$2"
				shift
				;;
			--log=*)
				_arg_log="${_key##--log=}"
				;;
			-l*)
				_arg_log="${_key##-l}"
				;;
			-r|--no-release|--release)
				_arg_release="on"
				test "${1:0:5}" = "--no-" && _arg_release="off"
				;;
			-r*)
				_arg_release="on"
				_next="${_key##-r}"
				if test -n "$_next" -a "$_next" != "$_key"
				then
					begins_with_short_option "$_next" && shift && set -- "-r" "-${_next}" "$@" || die "The short option '$_key' can't be decomposed to ${_key:0:2} and -${_key:2}, because ${_key:0:2} doesn't accept value and '-${_key:2:1}' doesn't correspond to a short option."
				fi
				;;
			-n|--no-norun|--norun)
				_arg_norun="on"
				test "${1:0:5}" = "--no-" && _arg_norun="off"
				;;
			-n*)
				_arg_norun="on"
				_next="${_key##-n}"
				if test -n "$_next" -a "$_next" != "$_key"
				then
					begins_with_short_option "$_next" && shift && set -- "-n" "-${_next}" "$@" || die "The short option '$_key' can't be decomposed to ${_key:0:2} and -${_key:2}, because ${_key:0:2} doesn't accept value and '-${_key:2:1}' doesn't correspond to a short option."
				fi
				;;
			-h|--help)
				print_help
				exit 0
				;;
			-h*)
				print_help
				exit 0
				;;
			*)
				_PRINT_HELP=yes die "FATAL ERROR: Got an unexpected argument '$1'" 1
				;;
		esac
		shift
	done
}

parse_commandline "$@"

# ])

#
# Building the bootloader
#
echo "> Building the bootloader"
UEFI_TARGET="x86_64-uefi"
if [ "$_arg_release" == "on" ]; then
	UEFI_BUILD_ARGS="--release"
    UEFI_BUILD_DIR="`pwd`/../target/$UEFI_TARGET/release"
else
	UEFI_BUILD_ARGS=""
	UEFI_BUILD_DIR="`pwd`/../target/$UEFI_TARGET/debug"
fi

ESP_DIR=$UEFI_BUILD_DIR/esp

cd ../bootloader
RUST_TARGET_PATH=`pwd` xargo build --target $UEFI_TARGET --package bootloader $UEFI_BUILD_ARGS

QEMU_UEFI_APPEND="-drive if=pflash,format=raw,file=`pwd`/OVMF_CODE.fd,readonly=on"
QEMU_UEFI_APPEND+=" -drive if=pflash,format=raw,file=`pwd`/OVMF_VARS.fd,readonly=on"
QEMU_UEFI_APPEND+=" -device ahci,id=ahci,multifunction=on"
QEMU_UEFI_APPEND+=" -drive if=none,format=raw,file=fat:rw:$ESP_DIR,id=esp"
QEMU_UEFI_APPEND+=" -device ide-drive,bus=ahci.0,drive=esp"

rm -rf $ESP_DIR/EFI
mkdir -p $ESP_DIR/EFI/Boot
cp $UEFI_BUILD_DIR/bootloader.efi $ESP_DIR/EFI/Boot/BootX64.efi

#
# Building the kernel
#
echo "> Building the kernel"
cd ../kernel
BESPIN_TARGET=x86_64-bespin

export PATH=`pwd`/../binutils-2.30.90/bin:$PATH
if [ -x "$(command -v x86_64-elf-ld)" ] ; then
    # On non-Linux system we should use the cross-compiled linker from binutils
    export CARGO_TARGET_X86_64_BESPIN_LINKER=x86_64-elf-ld
    OBJCOPY=x86_64-elf-objcopy
else
    OBJCOPY=objcopy
fi

BUILD_ARGS="--target=$BESPIN_TARGET"

if [ "$_arg_release" == "on" ]; then
    BUILD_ARGS="$BUILD_ARGS --release"
fi

if [ "${_arg_features}" != "" ]; then
    BUILD_ARGS="$BUILD_ARGS --features $_arg_features"
fi

BESPIN_TARGET=x86_64-bespin RUST_TARGET_PATH=`pwd`/src/arch/x86_64 xargo build $BUILD_ARGS

if [ "$_arg_release" == "off" ]; then
    cp ../target/$BESPIN_TARGET/debug/bespin kernel
	cp ../target/$BESPIN_TARGET/debug/bespin $ESP_DIR/kernel
    $OBJCOPY ../target/$BESPIN_TARGET/debug/bespin -F elf32-i386 mbkernel
else
    cp ../target/$BESPIN_TARGET/release/bespin kernel
	cp ../target/$BESPIN_TARGET/release/bespin $ESP_DIR/kernel
    $OBJCOPY ../target/$BESPIN_TARGET/release/bespin -F elf32-i386 mbkernel
fi

find $ESP_DIR

if [ "${_arg_norun}" != "on" ]; then

    CMDLINE_APPEND=""
    if [ "${_arg_log}" != "" ]; then
        CMDLINE_APPEND="-append log=$_arg_log"
    fi

    set +e
    cat /proc/modules | grep kvm_intel
    if [ $? -eq 0 ]; then
        KVM_ARG='-enable-kvm -cpu host,migratable=no,+invtsc,+tsc'
		KVM_ARG='-cpu qemu64'
    else
        KVM_ARG='-cpu qemu64'
    fi

    QEMU_NET_APPEND="-net nic,model=e1000,netdev=n0 -netdev tap,id=n0,script=no,ifname=tap0"

	# QEMU Monitor for debug: https://en.wikibooks.org/wiki/QEMU/Monitor
	QEMU_MONITOR="-monitor telnet:127.0.0.1:55555,server,nowait -d guest_errors -d int -D debuglog.out"

    # Create a tap interface to communicate with guest and give it an IP
    sudo tunctl -t tap0 -u $USER -g `id -gn`
    sudo ifconfig tap0 ip 172.31.0.20/24

	#QEMU_NET_APPEND="-net nic,model=e1000 -net user"
	# -kernel ./mbkernel -initrd kernel
    qemu-system-x86_64 $KVM_ARG -m 1024 -smp 2 -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04 $QEMU_UEFI_APPEND $QEMU_NET_APPEND $CMDLINE_APPEND $QEMU_MONITOR
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
