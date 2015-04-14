#!/usr/bin/env bash

BASEDIR=$(dirname $0)
if [ $# -eq 0 ]; then
    BASE=.
else
    BASE=$1
fi

# Tuprules
rm $BASE/Tuprules.lua 2> /dev/null
rm $BASE/Tupfile.lua 2> /dev/null

# This should not be a symlink since we modify it in case we build in-tree
ln -s ./tup/Tuprules.lua.root $BASE/Tuprules.lua
ln -s ./tup/Tupfile.lua.root $BASE/Tupfile.lua

if [ ! -f $BASE/blacklist.lua ]; then
    cp $BASE/tup/blacklist.lua $BASE/blacklist.lua
fi
if [ ! -f $BASE/whitelist.lua ]; then
    cp $BASE/tup/whitelist.lua $BASE/whitelist.lua
fi

echo "Your tree is now ready for tup build!"
echo "Initialize tup for the first time by running init:"
echo " $ tup init"
echo "The next step is to add a variant:"
echo " $ tup variant tup/x86_64.config"
echo "Then build that variant:"
echo " $ tup"
echo "For more information, have a look at tup/README.md"
command -v tup >/dev/null 2>&1 || { echo -e >&2 "I have not found tup on your path.\n You can install it by following the instructions in $BASEDIR/tup/README.md."; exit 1; }
