#!/bin/sh

USELTP=1
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_yield -n 0
echo "*** RT_$tid: PASSED"
echo ""

tid=001
echo "*** LT_$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork01 2>&1 | tee ./LT_${tid}.txt
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
sudo ${MCEXEC} ${LTPBIN}/fork02 2>&1 | tee ./LT_${tid}.txt
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
sudo ${MCEXEC} ${LTPBIN}/fork03 2>&1 | tee ./LT_${tid}.txt
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
sudo ${MCEXEC} ${LTPBIN}/fork04 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=005
echo "*** LT_$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork07 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=006
echo "*** LT_$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork08 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

