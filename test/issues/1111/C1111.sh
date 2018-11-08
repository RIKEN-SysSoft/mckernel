#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** RT_${tid} start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s rt_sigaction -n 5 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_${tid}: PASSED"
else
	echo "*** RT_${tid}: FAILED"
fi
echo ""

sudo ${MCEXEC} ./CT_001
sudo ${MCEXEC} ./CT_002
sudo ${MCEXEC} ./CT_003
sudo ${MCEXEC} ./CT_004
sudo ${MCEXEC} ./CT_005

