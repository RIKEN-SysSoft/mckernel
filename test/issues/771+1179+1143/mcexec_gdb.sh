#!/bin/sh -x

if [ x$MCEXEC = x ]; then
	echo MCEXEC was not set >&2
	exit 1
fi

exec $MCEXEC gdb "$@"
