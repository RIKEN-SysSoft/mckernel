#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1174
tid=01
echo "*** C$issueT$tid start *******************************"
echo "execute:  mcexec ls -ld /proc/*/* &> /dev/null"
${MCEXEC} ls -ld /proc/*/* &> /dev/null
if [ $? -ne 0 ]; then
	echo "*** C$issue$tid: PASSED"
else
	echo "*** C$issue$tid: FAILED"
fi
echo ""

tid=02
echo "*** C$issueT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve01 \
2>&1 | tee ./C${issue}T${tid}.txt
ok=`grep TPASS C${issue}T${tid}.txt | wc -l`
ng=`grep TFAIL C${issue}T${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** C${issue}T$tid: PASSED (ok:$ok)"
else
	echo "*** C${issue}T$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=03
echo "*** C$issueT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve02 \
2>&1 | tee ./C${issue}T${tid}.txt
ok=`grep TPASS C${issue}T${tid}.txt | wc -l`
ng=`grep TFAIL C${issue}T${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** C${issue}T$tid: PASSED (ok:$ok)"
else
	echo "*** C${issue}T$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=04
echo "*** C$issueT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve03 \
2>&1 | tee ./C${issue}T${tid}.txt
ok=`grep TPASS C${issue}T${tid}.txt | wc -l`
ng=`grep TFAIL C${issue}T${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** C${issue}T$tid: PASSED (ok:$ok)"
else
	echo "*** C${issue}T$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=05
echo "*** C$issueT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve05 \
20 ${LTPBIN}/execve05 ${LTPBIN}/execve05 4 2>&1 | tee ./C${issue}T${tid}.txt
ok=`grep TPASS C${issue}T${tid}.txt | wc -l`
ng=`grep TFAIL C${issue}T${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** C${issue}T$tid: PASSED (ok:$ok)"
else
	echo "*** C${issue}T$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""
