#!/bin/sh

TESTNAME=CT_005

. ./config

SIG_NAME=SIGTERM
SIG_NUM=15

fail=0

echo "*** ${TESTNAME} start *******************"
echo "** exec ostest siginfo_01 and then send ${SIG_NAME} to mcexec"
${MCEXEC} ${OSTEST_DIR}/bin/test_mck -s siginfo -n 1 &
sleep 1

echo "** back ground process(mcexec): $!"
echo "** send ${SIG_NAME} to mcexec once"
kill -${SIG_NUM} $!
sleep 1

echo "** check existing of $!"
ps -p $!

if [ $? = 0 ]; then
	echo "[OK] $! exists yet"
else
	echo "[NG] $! doesn't exist"
	fail=1
fi

echo "** send ${SIG_NAME} to mcexec again"
kill -${SIG_NUM} $!
sleep 1
echo "** check existing of $!"
ps -p $!

if [ $? != 0 ]; then
	echo "[OK] $! doesn't exist (be killed by signal)"
else
	echo "[NG] exist yet"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

