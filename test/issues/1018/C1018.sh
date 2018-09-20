#!/bin/sh
if [ -f $HOME/mck_test_config ]; then
	. $HOME/mck_test_config
else
	BIN=
	SBIN=
	OSTEST=
fi
BOOTPARAM="-c 1-7,9-15,17-23,25-31 -m 10G@0,10G@1 -r 1-7:0+9-15:8+17-23:16+25-31:24"

if [ "x$BINDIR" = x ];then
	BINDIR="$BIN"
fi

if [ "x$SBINDIR" = x ];then
	SBINDIR="$SBIN"
fi

if [ "x$OSTESTDIR" = x ]; then
	OSTESTDIR="$OSTEST"
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
	echo mcexec: not found >&2
	exit 1
fi

$BINDIR/mcexec ./CT_001
$BINDIR/mcexec ./CT_002

tid=001
echo "*** RT_$tid start *******************************"
sudo $BINDIR/mcexec $OSTESTDIR/bin/test_mck -s procfs -n 0 2>&1 | tee ./RT_${tid}.txt
if grep -v "RESULT: TP failed" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=002
echo "*** RT_$tid start *******************************"
sudo $BINDIR/mcexec $OSTESTDIR/bin/test_mck -s procfs -n 1 2>&1 | tee ./RT_${tid}.txt
if grep -v "RESULT: TP failed" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=003
echo "*** RT_$tid start *******************************"
sudo $BINDIR/mcexec $OSTESTDIR/bin/test_mck -s procfs -n 3 2>&1 | tee ./RT_${tid}.txt
if grep -v "RESULT: TP failed" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""
