#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_getaffinity -n 1 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=002
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_getaffinity -n 0 -- -p 20 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=003
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_getaffinity -n 2 -- -p 20 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=004
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_getaffinity -n 3 -- -p 20 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""

tid=005
echo "*** RT_$tid start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s sched_getaffinity -n 5 -- -p 20 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_$tid: PASSED"
else
	echo "*** RT_$tid: FAILED"
fi
echo ""
