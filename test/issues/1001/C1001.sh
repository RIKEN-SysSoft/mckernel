#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

${MCEXEC} ./CT_001
${MCEXEC} ./CT_002
./CT_003
./CT_004

tid=001
echo "*** LT_$tid start *******************************"
${MCEXEC} ${LTPBIN}/perf_event_open01 2>&1 | tee ./LT_${tid}.txt
ok=`grep TPASS LT_${tid}.txt | wc -l`
ng=`grep TFAIL LT_${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** LT_$tid: PASSED (ok:$ok)"
else
	echo "*** LT_$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""
