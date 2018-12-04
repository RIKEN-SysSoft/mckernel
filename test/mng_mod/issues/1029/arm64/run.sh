#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../../../common.sh

STRESSBIN=

${STRESSBIN}/mck-mcexec.sh ${STRESSBIN}/killit -np 16 -nosignal ${STRESSBIN}/signalonfutex
if [ $? == 0 ]; then
	echo "ISSUE01: OK"
else
	echo "ISSUE01: NG"
fi

mcstop
mcreboot

${MCEXEC} ./go_test 10 > /dev/null
${IHKOSCTL} 0 kmsg | grep CT_ | cut -f 2 -d ":" | sort
