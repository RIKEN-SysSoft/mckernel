#!/bin/sh
BIN=
SBIN=
OSTEST=
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

if [ -f $HOME/ostest/bin/test_mck ]; then
	OSTESTDIR="$HOME/ostest"
fi

if [ "x$OSTESTDIR" = x ]; then
	OSTESTDIR="$OSTEST"
fi

if [ ! -x "$OSTESTDIR"/bin/test_mck ]; then
	echo no ostest found >&2
	exit 1
fi

if lsmod | grep mcctrl > /dev/null 2>&1; then
	sudo $SBINDIR/mcstop+release.sh
fi
if ! lsmod | grep mcctrl > /dev/null 2>&1; then
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
fi
if ! lsmod | grep mcctrl > /dev/null 2>&1; then
	echo no mcctrl.ko found >&2
	exit 1
fi

$BINDIR/mcexec ./C765

$BINDIR/mcexec "$OSTESTDIR"/bin/test_mck -s mem_limits -n 0 -- -f mmap -s 7340032 -c 1

if $SBINDIR/ihkosctl 0 kmsg | grep -i bad > /dev/null 2>&1; then
	$SBINDIR/ihkosctl 0 kmsg
	echo C765T09 NG
else
	echo C765T09 OK
fi
