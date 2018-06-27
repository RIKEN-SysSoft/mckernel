#!/bin/sh
BIN=
SBIN=
OSTEST=
BOOTPARAM="-c 1-7,9-15,17-23,25-31 -m 10G@0,10G@1 -r 1-7:0+9-15:8+17-23:16+25-31:24"

if [ -f ../../../config.h ]; then
	str=`grep "^#define BINDIR " ../../../config.h | head -1 | sed 's/^#define BINDIR /BINDIR=/'`
	eval $str
fi
if [ "x$BINDIR" = x ];then
	BINDIR="$BIN"
fi

if [ -f ../../../Makefile ]; then
	str=`grep ^SBINDIR ../../../Makefile | head -1 | sed 's/ //g'`
	eval $str
fi
if [ "x$SBINDIR" = x ];then
	SBINDIR="$SBIN"
fi

if [ -f $HOME/ostest/bin/test_mck ]; then
	OSTESTDIR=$HOME/ostest/
fi
if [ "x$OSTESTDIR" = x ]; then
	OSTESTDIR="$OSTEST"
fi

if [ ! -x $SBINDIR/mcstop+release.sh ]; then
	echo mcstop+release: not found >&2
	exit 1
fi
echo -n "mcstop+release.sh ... "
sudo $SBINDIR/mcstop+release.sh
echo "done"

if [ ! -x $SBINDIR/mcreboot.sh ]; then
	echo mcreboot: not found >&2
	exit 1
fi
echo -n "mcreboot.sh $BOOTPARAM ... "
sudo $SBINDIR/mcreboot.sh $BOOTPARAM
echo "done"

if [ ! -x $BINDIR/mcexec ]; then
	echo mcexec: not found >&2
	exit 1
fi

echo "*** RT_001 start *******************************"
sudo $BINDIR/mcexec $OSTESTDIR/bin/test_mck -s rt_sigaction -n 4
echo "*** RT_001: CHECK \"Terminate by signal 10\""
echo ""

sudo $BINDIR/mcexec ./CT_001
sudo $BINDIR/mcexec ./CT_002
sudo $BINDIR/mcexec ./CT_003
sudo $BINDIR/mcexec ./CT_004
sudo $BINDIR/mcexec ./CT_005

