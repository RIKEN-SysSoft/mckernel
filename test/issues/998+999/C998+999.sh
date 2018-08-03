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
	echo mcexec: not found >&2
	exit 1
fi

for i in {1..10}; do
	for j in {1..100}; do
		$BINDIR/mcexec "$TESTMCK" -s wait4 -n 3 > testmck.log 2>&1
		if [ $? != 0 ]; then
			echo "****** ERROR ******"
			cat testmck.log
			exit 1
		fi
		echo -n .
	done
	echo
	echo "*** $i"00" ****************************"
done

echo "*** C998+999 OK ****************************"
