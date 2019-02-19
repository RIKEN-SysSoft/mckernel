#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

tid=001
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/nftw01 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi

echo ""
tid=002
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/nftw6401 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
