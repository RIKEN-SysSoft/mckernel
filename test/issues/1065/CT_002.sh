#!/bin/sh

TESTNAME=CT_002
arg_path=./dummy_file

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
real_path=`realpath ${arg_path}`

echo "file map: ${arg_path}"

${MCEXEC} ./file_map ${arg_path} | tee  ./${TESTNAME}.log
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./${TESTNAME}.log 

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

rm ./${TESTNAME}.log
