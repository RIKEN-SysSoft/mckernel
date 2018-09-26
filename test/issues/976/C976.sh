#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

${MCEXEC} ./CT_001
${MCEXEC} ./CT_002
${MCEXEC} ./CT_003

tid=001
echo "*** LT_$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve01 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=002
echo "*** LT_$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve02 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=003
echo "*** LT_$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve03 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=004
echo "*** LT_$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve05 20 ${LTPBIN}/execve05 ${LTPBIN}/execve05 4 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

