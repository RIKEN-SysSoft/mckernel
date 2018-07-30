#!/bin/sh
BIN=
SBIN=
BOOTPARAM="-c 1-7 -m 2G@0"

if [ -f ../../../config.h ]; then
	str=`grep "^#define BINDIR " ../../../config.h | head -1 | sed 's/^#define BINDIR /BINDIR=/'`
	eval $str
fi

if [ -f ../../../Makefile ]; then
	str=`grep ^SBINDIR ../../../Makefile | head -1 | sed 's/ //g'`
	eval $str
fi

if [ "x$BINDIR" = x ];then
	BINDIR="$BIN"
fi
if [ "x$SBINDIR" = x ];then
	SBINDIR="$SBIN"
fi

if ! lsmod | grep mcctrl > /dev/null 2>&1; then
	$SBINDIR/mcreboot.sh $BOOTPARAM
fi

$BINDIR/mcexec ./C926
