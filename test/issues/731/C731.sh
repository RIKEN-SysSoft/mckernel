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

if ! lsmod | grep mcctrl > /dev/null 2>&1; then
	if [ ! -x $SBINDIR/mcreboot.sh ]; then
		echo no mcreboot found >&2
		exit 1
	fi
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
fi

if [ ! -x $BINDIR/mcexec ]; then
	echo no mcexec found >&2
	exit 1
fi

sudo $BINDIR/mcexec ./g310a 2>&1 | tee g310a.txt
if grep "fork: Permission denied" g310a.txt > /dev/null 2>&1 ; then
	echo "*** C731T001: g310a OK"
else
	echo "*** C731T001: g310a NG"
fi

if [ x$LTPDIR = x ]; then
	echo no LTP found >&2
	exit 1
fi

for i in 01:002 02:003 03:004 04:005 07:006 08:007; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$BINDIR/mcexec $LTPDIR/bin/fork$tp 2>&1 | tee fork$tp.txt
	ok=`grep TPASS fork$tp.txt | wc -l`
	ng=`grep TFAIL fork$tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C731T$id: fork$tp OK ($ok)"
	else
		echo "*** C731T$id: fork$tp NG (ok=$ok ng=%ng)"
	fi
done
