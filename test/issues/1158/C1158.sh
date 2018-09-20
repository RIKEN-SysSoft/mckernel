#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

tid=001
echo "*** CT_$tid start *******************************"
tgt_file=`find /sys/devices/ -name local_cpus | head -n 1`
echo "[Linux   ] cat ${tgt_file}"
cat ${tgt_file} | tee ./CT_${tid}_lnx.txt
echo "[McKernel] mcexec cat ${tgt_file}"
${MCEXEC} cat ${tgt_file} | tee ./CT_${tid}_mck.txt

diff ./CT_${tid}_lnx.txt ./CT_${tid}_mck.txt &> /dev/null

if [ $? == 0 ]; then
	echo "[OK] local_cpus is same between Linux and McKernel"
	echo "*** CT_$tid: PASSED"
else
	echo "[NG] local_cpus is NOT same between Linux and McKernel"
	echo "*** CT_$tid: FAILED"
fi
echo ""

tid=002
echo "*** CT_$tid start *******************************"
tgt_file=`find /sys/devices/ -name local_cpulist | head -n 1`
echo "[Linux   ] cat ${tgt_file}"
cat ${tgt_file} | tee ./CT_${tid}_lnx.txt
echo "[McKernel] mcexec cat ${tgt_file}"
${MCEXEC} cat ${tgt_file} | tee ./CT_${tid}_mck.txt

diff ./CT_${tid}_lnx.txt ./CT_${tid}_mck.txt &> /dev/null

if [ $? == 0 ]; then
	echo "[OK] local_cpulist is same between Linux and McKernel"
	echo "*** CT_$tid: PASSED"
else
	echo "[NG] local_cpulist is NOT same between Linux and McKernel"
	echo "*** CT_$tid: FAILED"
fi
echo ""

