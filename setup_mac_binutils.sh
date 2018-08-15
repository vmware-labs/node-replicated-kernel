#!/bin/bash
set -exu

BINUTILS=binutils-2.30.90
BINUTILS_INSTALL_PATH=$BINUTILS

if [ ! -x "$(command -v $BINUTILS/bin/x86_64-elf-ld)" ] ; then
    wget ftp://sourceware.org/pub/binutils/snapshots/$BINUTILS.tar.xz
    tar zxf $BINUTILS.tar.xz

    cd $BINUTILS
    ./configure --target=x86_64-elf --prefix=`pwd` \
        --disable-nls --disable-werror \
        --disable-gdb --disable-libdecnumber --disable-readline --disable-sim
    make -j4
    make install
    cd ..
    rm $BINUTILS.tar.xz
fi
