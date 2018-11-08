#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

. ./config

result=0

${MCSTOP}
${MCREBOOT} -c 4-7 -m 1G@0,1G@1,1G@2,1G@3 -O

for i in `seq 1 5`
do
	${STRESSBIN}/killit -np 16 -t 2000 ${MCEXEC} ${STRESSBIN}/signalonfork -nosignal > /dev/null 2>&1
	if [ $? != 0 ]; then
		result=-1
	fi

	pidof mcexec > /dev/null 2>&1
	if [ $? == 0 ]; then
		result=-1
	fi

	${IHKOSCTL} 0 ioctl 40000000 1
	${IHKOSCTL} 0 ioctl 40000000 2

	output=`${IHKOSCTL} 0 kmsg`
	echo ${output} | grep -q "0 processes are found"
	if [ $? != 0 ]; then
		result=-1
	fi

	echo ${output} | grep -q "0 threads are found"
	if [ $? != 0 ]; then
		result=-1
	fi
done

if [ ${result} == 0 ]; then
	echo "CT1001-3: OK"
else
	echo "CT1001-3: NG"
fi

while read line
do
	${MCEXEC} ${LTPBIN}/${line} > /dev/null
	if [ $? == 0 ]; then
		echo "${line}: OK"
	else
		echo "${line}: NG"
		result=-1
	fi
done < ./ltplist.txt

${MCSTOP}

exit ${result}
