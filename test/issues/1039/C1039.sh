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
if [ x$LTPDIR = x ]; then
	echo no LTP found >&2
	exit 1
fi

for i in fork02:01 fork03:02 execve01:03 execve02:04 execve03:05 mmap12:06; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo sh -c "PATH=$LTPDIR/bin:$PATH $BINDIR/mcexec $LTPDIR/bin/$tp" 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1039T$id: $tp OK ($ok)"
	else
		echo "*** C1039T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
