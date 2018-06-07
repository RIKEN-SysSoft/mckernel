#!/bin/sh

TESTNAME=CT_002

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
echo "** exec ostest siginfo_00"
${MCEXEC} ${OSTEST_DIR}/bin/test_mck -s siginfo -n 0| tee -a ./${TESTNAME}.log

tail -n 1 ./${TESTNAME}.log | grep -a -e "RESULT: ok" &> /dev/null

if [ $? = 0 ]; then
	echo "[OK] ostest siginfo_00  passed"
else
	echo "[NG] ostest siginfo_00  failed"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

rm ./${TESTNAME}.log
