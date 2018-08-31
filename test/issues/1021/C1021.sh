#!/bin/sh
BIN=
SBIN=
LTP=
OSTEST=
BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"

if ! sudo ls /sys/kernel/debug | grep kmemleak > /dev/null 2>&1; then
	echo kmemleak: not found >&2
	exit 1
fi

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

if [ -f $HOME/ltp/testcases/bin/fork01 ]; then
	LTPDIR=$HOME/ltp
fi
if [ "x$LTPDIR" = x ]; then
	LTPDIR="$LTP"
fi
if [ "x$LTPDIR" != x ]; then
	LTPDIR="$LTPDIR/testcases"
fi

if [ -f $HOME/ostest/bin/test_mck ]; then
	OSTESTDIR=$HOME/ostest/
fi
if [ "x$OSTESTDIR" = x ]; then
	OSTESTDIR="$OSTEST"
fi
if [ ! -x "$OSTESTDIR"/bin/test_mck ]; then
	echo no ostest found $OSTEST >&2
	exit 1
fi
TESTMCK="$OSTESTDIR/bin/test_mck"

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
	echo no mcexec found >&2
	exit 1
fi

################################################################################
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
$BINDIR/mcexec ./C1021
sudo $SBINDIR/mcstop+release.sh
sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
if sudo cat /sys/kernel/debug/kmemleak | tee C1021T71.kmemleak | grep 'mcctrl'; then
	echo '*** C1021T61 NG (kmemleak)'
else
	echo '*** C1021T61 OK (kmemleak)'
fi
