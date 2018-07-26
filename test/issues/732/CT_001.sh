#!/bin/sh

TESTNAME=CT_001
tgt_file=maps

fail=0

. ./config

echo "*** ${TESTNAME} start ***************************"

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./${TESTNAME}.log 
tail -1 ${TESTNAME}.log | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

rm ./${TESTNAME}.log

if [ X${fail} != X0 ]; then
	echo "*** ${TESTNAME} FAILED"
else
	echo "*** ${TESTNAME} PASSED"
fi
echo ""
