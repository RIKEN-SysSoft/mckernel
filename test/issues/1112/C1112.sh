#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** RT_${tid} start *******************************"
sudo ${MCEXEC} ${TESTMCK} -s mremap_mmap_anon -n 1 2>&1 | tee ./RT_${tid}.txt
if grep "RESULT: ok" ./RT_${tid}.txt > /dev/null 2>&1 ; then
	echo "*** RT_${tid}: PASSED"
else
	echo "*** RT_${tid}: FAILED"
fi
echo ""

sudo $BINDIR/mcexec ./CT_001
sudo $BINDIR/mcexec ./CT_002
sudo $BINDIR/mcexec ./CT_003
sudo $BINDIR/mcexec ./CT_004
sudo $BINDIR/mcexec ./CT_005

