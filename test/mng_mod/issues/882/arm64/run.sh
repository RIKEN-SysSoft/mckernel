#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=1
USEOSTEST=0

. ../../../../common.sh

STRESSBIN=

result=0
for i in `seq 1 5`
do
	${STRESSBIN}/mck-mcexec.sh ${STRESSBIN}/killit -np 16 -t 4000 - ${STRESSBIN}/signalonfork -nosignal
	if [ $? != 0 ]; then
		result=-1
		break
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

exit ${result}
