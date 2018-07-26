#!/bin/sh

TESTNAME=CT_006

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
${MCEXEC} cat /proc/self/maps

if [ $? = 0 ]; then
	echo "[OK] shell script is running normaly"
else
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""
