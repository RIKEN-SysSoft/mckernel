#!/bin/sh

mcexec=`which mcexec`
gdb=@GDB@

$mcexec $gdb "$@"

