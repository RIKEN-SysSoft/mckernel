#!/bin/sh

TESTNAME=CT_004
test_program=./print_maps

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
real_path=`realpath ${test_program}`
interp_path=`readelf -l ${test_program} | grep "interpreter:" | sed -r 's/.*\[.*interpreter:\s(.*)\].*/\1/'`
interp_real_path=`realpath ${interp_path}`

echo "exec : ${test_program}"

${MCEXEC} ${test_program} | tee  ./${TESTNAME}.log
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

echo ""
echo "** grep ${interp_real_path} from maps"
grep -a -e "${interp_real_path}$" ./${TESTNAME}.log 

if [ X$? = X0 ]; then
	echo "[OK] ${interp_real_path} is found"
else
	echo "[NG] ${interp_real_path} is not found"
	fail=1
fi


if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

rm ./${TESTNAME}.log
