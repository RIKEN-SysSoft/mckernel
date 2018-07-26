#!/bin/sh

TESTNAME=CT_001
REP=30

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
echo "** exec ltp-syscall_mkdir09  ${REP} times"
echo -n "" > ./${TESTNAME}.log
for i in `seq 1 ${REP}`
do
	${MCEXEC} ${LTP_DIR}/testcases/bin/mkdir09 | tee -a ./${TESTNAME}.log
done

grep -a -e "FAIL" ./${TESTNAME}.log

if [ $? != 0 ]; then
	echo "[OK] ltp-syscall_mkdir09  ${REP} times all passed"
else
	echo "[NG] ltp-syscall_mkdir09  failed"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

rm ./${TESTNAME}.log
