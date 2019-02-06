#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

CYCLE=50
REPS=100
cnt=0

tid=001
echo "*** CT$tid start *******************************"
echo -n "" > ./CT${tid}.txt
for i in `seq 1 ${CYCLE}`
do
	for j in `seq 1 ${REPS}`
	do
		${MCEXEC} ${TESTMCK} -s ptrace -n 15 > /dev/null 2>&1

		${IHKOSCTL} 0 clear_kmsg
		${IHKOSCTL} 0 ioctl 40000000 1
		${IHKOSCTL} 0 kmsg > ./tmp_out.txt

		if grep "0 processes are found" ./tmp_out.txt \
				> /dev/null 2>&1 ; then
			echo "[OK] process is not found" >> ./CT${tid}.txt
		else
			echo "[NG] process is found" >> ./CT${tid}.txt
		fi
	done
	if grep "[NG]" ./CT${tid}.txt > /dev/null 2>&1; then
		echo "[NG] fail occurred"
		echo "*** CT${tid}: FAILED"
		exit 1
	else
		cnt=`expr ${cnt} + ${REPS}`
		echo "[OK] ${cnt} times succeed"
	fi
done
echo "*** CT${tid}: PASSED"

