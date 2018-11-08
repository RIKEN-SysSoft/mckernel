#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** RT_${tid} start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s rt_sigaction -n 4
echo "*** RT_${tid}: CHECK \"Terminate by signal 10\""
echo ""

sudo ${MCEXEC} ./CT_001
sudo ${MCEXEC} ./CT_002
sudo ${MCEXEC} ./CT_003
sudo ${MCEXEC} ./CT_004
sudo ${MCEXEC} ./CT_005

