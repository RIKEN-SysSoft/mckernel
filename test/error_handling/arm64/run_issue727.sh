#!/bin/sh
## run_issue727.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

result=-1

########################
# Issue727 test(patch) #
########################

make

${MCEXEC} ./exec
if [ $? != 0 ]; then
	output=`${IHKOSCTL} 0 get status`
	echo "${output}" | grep -q "PANIC"
	if [ $? == 1 ]; then
		echo "Issue727_0002: OK"
		result=0
	else
		echo "McKernel PANIC detected."
	fi
fi

if [ ${result} != 0 ]; then
	echo "Issue727_0002: NG"
fi

exit ${result}
