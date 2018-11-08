#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

strace -f -c -o ./CT_001.strc $BINDIR/mcexec ./CT_001

tid=002
echo "*** CT_$tid start *******************************"
echo "* Check syscall_time is not delegated to mcexec"
echo "* Result of strace -f -c (expect time is NOT contained)"
cat ./CT_001.strc

grep -e "time$" ./CT_001.strc &> /dev/null
if [ $? != 0 ]; then
	echo "*** CT_$tid: PASSED"
else
	echo "*** CT_$tid: FAILED"
fi
echo ""

tid=001
echo "*** LT_$tid start *******************************"
$BINDIR/mcexec $LTPDIR/bin/time01 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
    echo "*** LT_$tid: PASSED (ok:$ok)"
else
    echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=002
echo "*** LT_$tid start *******************************"
$BINDIR/mcexec $LTPDIR/bin/time02 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
    echo "*** LT_$tid: PASSED (ok:$ok)"
else
    echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=003
echo "*** LT_$tid start *******************************"
$BINDIR/mcexec $LTPDIR/bin/gettimeofday01 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
    echo "*** LT_$tid: PASSED (ok:$ok)"
else
    echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=004
echo "*** LT_$tid start *******************************"
$BINDIR/mcexec $LTPDIR/bin/gettimeofday02 2>&1 | tee ./LT_${tid}.txt
ok=`grep PASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
    echo "*** LT_$tid: PASSED (ok:$ok)"
else
    echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

