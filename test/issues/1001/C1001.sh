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
./CT_003
./CT_004

tid=001
echo "*** LT_$tid start *******************************"
$BINDIR/mcexec $LTPDIR/bin/perf_event_open01 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""
