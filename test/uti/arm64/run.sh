#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2019 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

for i in `seq 12 20`
do
	${MCEXEC} --enable-uti ./CT${i}
	if [ $? == 0 ]; then
		echo "CT${i}: OK."
	else
		echo "CT${i}: NG."
	fi
done

mcstop
