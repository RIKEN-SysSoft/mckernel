#!/bin/sh

TESTNAME=CT_008
exec_program="./print_maps_and_cmdline"
test_program="./call_execve.sh ${exec_program}"

. ./config

fail=0

echo "*** ${TESTNAME} start *******************"
real_path=`realpath ${exec_program}`
interp_path=`readelf -l ${exec_program} | grep "interpreter:" | sed -r 's/.*\[.*interpreter:\s(.*)\].*/\1/'`
interp_real_path=`realpath ${interp_path}`

echo "exec : ${test_program}"

${MCEXEC} ${test_program} 1> ./${TESTNAME}_maps.log 2> ./${TESTNAME}_cmdline.log
if [ X$? != X0 ]; then
	fail=1
fi

cat ./${TESTNAME}_maps.log
echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./${TESTNAME}_maps.log 

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

echo ""
echo "** grep ${interp_real_path} from maps"
grep -a -e "${interp_real_path}$" ./${TESTNAME}_maps.log 

if [ X$? = X0 ]; then
	echo "[OK] ${interp_real_path} is found"
else
	echo "[NG] ${interp_real_path} is not found"
	fail=1
fi

cat ./${TESTNAME}_cmdline.log
echo ""
echo "** grep ${exec_program} from cmdline"
grep -a -e "${exec_program}" ./${TESTNAME}_cmdline.log 

if [ X$? = X0 ]; then
	echo "[OK] ${exec_program} is found"
else
	echo "[NG] ${exec_program} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** ${TESTNAME} PASSED"
else
	echo "*** ${TESTNAME} FAILED"
fi
echo ""

#rm ./${TESTNAME}_maps.log
#rm ./${TESTNAME}_cmdline.log
