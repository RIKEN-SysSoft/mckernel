#!/bin/sh
BIN=
SBIN=
LTP=
BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"

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
	LTPDIR=$HOME/ltp/testcases
fi
if [ "x$LTPDIR" = x ]; then
	LTPDIR="$LTP"
fi

if [ ! -x $SBINDIR/mcreboot.sh ]; then
	echo no mcreboot found >&2
	exit 1
fi
if lsmod | grep mcctrl > /dev/null 2>&1; then
	sudo $SBINDIR/mcstop+release.sh
	if lsmod | grep mcctrl > /dev/null 2>&1; then
		echo shutdown failed >&2
		exit 1
	fi
fi
sudo $SBINDIR/mcreboot.sh $BOOTPARAM
if ! lsmod | grep mcctrl > /dev/null 2>&1; then
	echo reboot failed >&2
	exit 1
fi

if [ ! -x $BINDIR/mcexec ]; then
	echo no mcexec found >&2
	exit 1
fi

################################################################################
rm -f mcexec
ln -s $BINDIR/mcexec
./C1024T01
./mcexec ./C1024T02

if [ x$LTPDIR = x ]; then
	echo no LTP found >&2
	exit 1
fi

for i in process_vm_readv02:03 process_vm_readv03:04 process_vm_writev02:05; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $BINDIR/mcexec $LTPDIR/bin/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1024T$id: $tp OK ($ok)"
	else
		echo "*** C1024T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
