#!/bin/sh

mcexec=`which mcexec`
gdb=`which gdb`

exec sudo $mcexec 0 $gdb "$@"

