#!/usr/bin/bash

. ../../common.sh

ulimit -c unlimited

${MCEXEC} ./C1219

# Find mccore*
CORE=`ls -t | head -2 | grep mc`

if [ ! -z $CORE ]; then
    echo "[ OK ] core for McKernel process found"
else
    echo "[ NG ] core for McKernel process not found"
    exit 1
fi

if [ "`gdb ./C1219 ./$CORE -x ./gdb.cmd | grep -c LWP`" == "2" ]; then
    echo "[ OK ] # of threads is 2"
else
    echo "[ NG ] # of threads isn't 2"
fi
